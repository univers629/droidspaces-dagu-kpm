/* SPDX-License-Identifier: GPL-2.0-only */
/* Scope reboot(2) to KPM-owned fake PID namespaces. */

#include "abi.h"
#include "pid_namespace.h"
#include "reboot_syscalls.h"

#include <asm/current.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#define DAGU_PIDNS_MAX_LEVEL 32U

#define DAGU_LINUX_REBOOT_MAGIC1  0xfee1deadU
#define DAGU_LINUX_REBOOT_MAGIC2  0x28121969U
#define DAGU_LINUX_REBOOT_MAGIC2A 0x05121996U
#define DAGU_LINUX_REBOOT_MAGIC2B 0x16041998U
#define DAGU_LINUX_REBOOT_MAGIC2C 0x20112000U

#define DAGU_LINUX_REBOOT_CMD_RESTART  0x01234567U
#define DAGU_LINUX_REBOOT_CMD_HALT     0xcdef0123U
#define DAGU_LINUX_REBOOT_CMD_POWER_OFF 0x4321fedcU
#define DAGU_LINUX_REBOOT_CMD_RESTART2 0xa1b2c3d4U

#define DAGU_SIGKILL 9
#define DAGU_SIGHUP 1U
#define DAGU_SIGINT 2U
#define DAGU_EINVAL 22L

_Static_assert(__NR_reboot == 142, "ARM64 reboot syscall number changed");

typedef void *(*active_pid_ns_fn)(void *task);
typedef void (*read_lock_fn)(void *lock);
typedef int (*send_sig_fn)(int signal, void *task, int priv);

static active_pid_ns_fn active_pid_ns_ptr;
static read_lock_fn read_lock_ptr;
static read_lock_fn read_unlock_ptr;
static send_sig_fn send_sig_ptr;
static void *tasklist_lock_ptr;
static unsigned int installed;

static int has_valid_reboot_magic(unsigned int magic1, unsigned int magic2)
{
    return magic1 == DAGU_LINUX_REBOOT_MAGIC1 &&
           (magic2 == DAGU_LINUX_REBOOT_MAGIC2 ||
            magic2 == DAGU_LINUX_REBOOT_MAGIC2A ||
            magic2 == DAGU_LINUX_REBOOT_MAGIC2B ||
            magic2 == DAGU_LINUX_REBOOT_MAGIC2C);
}

static int is_owned_fake_pidns(void *ns)
{
    if (!ns || ns == dagu_pid_root() ||
        dagu_load_u32(ns, DAGU_PIDNS_LEVEL) == 0U ||
        dagu_load_u32(ns, DAGU_PIDNS_LEVEL) > DAGU_PIDNS_MAX_LEVEL)
        return 0;
    return dagu_load_ptr(ns, DAGU_PIDNS_NS_COMMON + 0x08U) ==
           dagu_pid_proc_operations();
}

static void before_reboot(hook_fargs4_t *args, void *unused)
{
    unsigned int magic1 = (unsigned int)syscall_argn(args, 0);
    unsigned int magic2 = (unsigned int)syscall_argn(args, 1);
    unsigned int command = (unsigned int)syscall_argn(args, 2);
    unsigned int exit_signal;
    void *ns;
    void *reaper;
    int signal_rc = 0;

    (void)unused;
    if (!has_valid_reboot_magic(magic1, magic2))
        return;

    ns = active_pid_ns_ptr(current);
    if (!is_owned_fake_pidns(ns))
        return;

    if (command == DAGU_LINUX_REBOOT_CMD_RESTART ||
        command == DAGU_LINUX_REBOOT_CMD_RESTART2)
        exit_signal = DAGU_SIGHUP;
    else if (command == DAGU_LINUX_REBOOT_CMD_POWER_OFF ||
             command == DAGU_LINUX_REBOOT_CMD_HALT)
        exit_signal = DAGU_SIGINT;
    else {
        args->ret = (unsigned long)-DAGU_EINVAL;
        args->skip_origin = 1;
        return;
    }

    /* Android's 4.19 pid_namespace layout places reboot after the 0x30-byte
     * work_struct (0x20 core + two 8-byte Android KABI reserves), pid_gid,
     * and hide_pid. proc_work is at +0x80; ns_common begins at +0xc0, so
     * reboot is +0xb8. The device config has no RANDSTRUCT feature enabled. */
    dagu_store_u32(ns, DAGU_INFERRED_PIDNS_REBOOT, exit_signal);

    /* Match reboot_pid_ns(): protect child_reaper lookup and signal it before
     * terminating the syscall caller. The do_exit guard then queues namespace
     * cleanup instead of entering the CONFIG_PID_NS=n BRK path. */
    read_lock_ptr(tasklist_lock_ptr);
    reaper = dagu_load_ptr(ns, DAGU_PIDNS_CHILD_REAPER);
    if (reaper)
        signal_rc = send_sig_ptr(DAGU_SIGKILL, reaper, 1);
    read_unlock_ptr(tasklist_lock_ptr);

    send_sig_ptr(DAGU_SIGKILL, current, 1);
    args->ret = 0;
    args->skip_origin = 1;
    logki("ds-dagu-v02: scoped reboot ns=%p cmd=0x%x reaper=%p signal_rc=%d\n",
          ns, command, reaper, signal_rc);
}

void dagu_reboot_syscalls_uninstall(void)
{
    if (!installed)
        return;
    fp_unhook_syscalln(__NR_reboot, before_reboot, 0);
    installed = 0U;
}

int dagu_reboot_syscalls_install(void)
{
    hook_err_t rc;

    if (installed)
        return -22;
    active_pid_ns_ptr = (active_pid_ns_fn)kallsyms_lookup_name("task_active_pid_ns");
    read_lock_ptr = (read_lock_fn)kallsyms_lookup_name("_raw_read_lock");
    read_unlock_ptr = (read_lock_fn)kallsyms_lookup_name("_raw_read_unlock");
    send_sig_ptr = (send_sig_fn)kallsyms_lookup_name("send_sig");
    tasklist_lock_ptr = (void *)kallsyms_lookup_name("tasklist_lock");
    if (!active_pid_ns_ptr || !read_lock_ptr || !read_unlock_ptr ||
        !send_sig_ptr || !tasklist_lock_ptr || !dagu_pid_root() ||
        !dagu_pid_proc_operations())
        return -2;

    rc = fp_hook_syscalln(__NR_reboot, 4, before_reboot, 0, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    installed = 1U;
    return 0;
}
