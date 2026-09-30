/* SPDX-License-Identifier: GPL-2.0-only */
/* Restore the pid_namespace references optimized out by CONFIG_PID_NS=n. */

#include "abi.h"
#include "pid_lifecycle.h"
#include "pid_namespace.h"

#include <hook.h>
#include <kallsyms.h>

#define DAGU_PIDNS_MAX_LEVEL 32U

static void *alloc_pid_target;
static void *delayed_put_pid_target;
static unsigned int installed;
static unsigned int live_fake_pids;

static void *pid_namespace_of(void *pid)
{
    unsigned int level;
    if (!pid)
        return 0;
    level = dagu_load_u32(pid, DAGU_PID_LEVEL);
    if (level > DAGU_PIDNS_MAX_LEVEL)
        return 0;
    return dagu_load_ptr(pid, DAGU_PID_FIRST_UPID + 16U * level + DAGU_UPID_NS);
}

static void alloc_after(hook_fargs1_t *args, void *unused)
{
    void *ns = (void *)args->arg0;
    void *pid = (void *)args->ret;
    unsigned int level;
    unsigned int number;
    (void)unused;
    if (!ns || ns == dagu_pid_root() || (unsigned long)pid >= (unsigned long)-4095L)
        return;
    level = dagu_load_u32(pid, DAGU_PID_LEVEL);
    if (level != dagu_load_u32(ns, DAGU_PIDNS_LEVEL) || level > DAGU_PIDNS_MAX_LEVEL ||
        pid_namespace_of(pid) != ns)
        return;
    /* Native alloc_pid() calls a compiled-out get_pid_ns(). */
    dagu_pid_namespace_get(ns);
    __atomic_add_fetch(&live_fake_pids, 1U, __ATOMIC_RELAXED);
    number = dagu_load_u32(pid, DAGU_PID_FIRST_UPID + 16U * level + DAGU_UPID_NR);
    if (number == 1U)
        dagu_pid_namespace_get(ns); /* proc_work / proc_mnt lifetime */
}

static void delayed_put_before(hook_fargs1_t *args, void *unused)
{
    void *pid;
    /* delayed_put_pid() receives &pid->rcu, not struct pid *. */
    void *ns;
    (void)unused;
    args->local.data0 = 0;
    if (!args->arg0)
        return;
    pid = (unsigned char *)args->arg0 - DAGU_PID_RCU_HEAD;
    ns = pid_namespace_of(pid);
    if (!ns || ns == dagu_pid_root())
        return;
    /* alloc_after()'s reference must survive the RCU callback: its origin
     * reads ns->pid_cachep and frees the PID object. */
    args->local.data0 = (unsigned long)ns;
}

static void delayed_put_after(hook_fargs1_t *args, void *unused)
{
    void *ns = (void *)args->local.data0;
    (void)unused;
    if (!ns)
        return;
    dagu_pid_namespace_put(ns);
    __atomic_sub_fetch(&live_fake_pids, 1U, __ATOMIC_RELAXED);
}

void dagu_pid_lifecycle_uninstall(void)
{
    if (installed & 2U)
        hook_unwrap(delayed_put_pid_target, delayed_put_before, delayed_put_after);
    if (installed & 1U)
        hook_unwrap(alloc_pid_target, 0, alloc_after);
    installed = 0;
}

int dagu_pid_lifecycle_install(void)
{
    hook_err_t rc;
    if (installed)
        return -22;
    alloc_pid_target = (void *)kallsyms_lookup_name("alloc_pid");
    delayed_put_pid_target = (void *)kallsyms_lookup_name("delayed_put_pid");
    if (!alloc_pid_target || !delayed_put_pid_target || !dagu_pid_root())
        return -2;
    rc = hook_wrap1(alloc_pid_target, 0, alloc_after, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    installed |= 1U;
    rc = hook_wrap1(delayed_put_pid_target, delayed_put_before,
                    delayed_put_after, 0);
    if (rc != HOOK_NO_ERR) {
        dagu_pid_lifecycle_uninstall();
        return -(int)rc;
    }
    installed |= 2U;
    return 0;
}
