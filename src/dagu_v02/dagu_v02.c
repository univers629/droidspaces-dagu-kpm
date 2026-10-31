/* SPDX-License-Identifier: GPL-2.0-only */
/* Droidspaces fake PID/IPC namespace adapter for this dagu boot. */

#include "abi.h"
#include "clone3.h"
#include "devtmpfs.h"
#include "ipc_namespace.h"
#include "mqueue.h"
#include "mqueue_core.h"
#include "mqueue_syscalls.h"
#include "nat66.h"
#include "userns.h"
#include "msg_core.h"
#include "msg_syscalls.h"
#include "sem_core.h"
#include "sem_syscalls.h"
#include "nsproxy_bridge.h"
#include "pid_exit_guard.h"
#include "pid_lifecycle.h"
#include "pid_namespace.h"
#include "proc_bridge.h"
#include "proc_mount_refs.h"
#include "proc_root_dedup.h"
#include "reboot_syscalls.h"
#include "status_bridge.h"
#include "usercopy.h"
#include "xt_addrtype.h"

#include <asm/current.h>
#include <common.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <log.h>
#include <syscall.h>
#include <symbol.h>

#define DAGU_MODULE_NAME "ds-dagu-abi-probe"
#define DAGU_EBUSY 16L

/*
 * ---- KernelPatch loader ABI retargeting ----------------------------------
 * These values are tied to the *exact* KernelPatch KPImg build that loads the
 * KPM. They can be overridden at compile time with -D so one source tree can
 * target several loader versions:
 *
 *   KernelPatch  kpver   unload_module - hook_syscalln   prologue[3]
 *   0.13.3       0xd03   0x3e00                          0xb4000c00
 *   0.13.5(-2)   0xd05   0x3920                          0xb4000c00
 *   0.13.14      0xd0e   0x3d00                          0xb4000c00
 *
 * prologue[0..2] are 0xa9bb7bfd / 0x910003fd / 0xa9025bf5 on all three.
 * Derive new values from a kpimg.elf with tools/kpm_retarget.py.
 * --------------------------------------------------------------------------
 */
#ifndef DAGU_KP_VER
#define DAGU_KP_VER 0xd03U
#endif

/* historical absolute pair kept for reference; only the delta is used */
#ifndef DAGU_KP_HOOK_SYSCALLN_LINK
#define DAGU_KP_HOOK_SYSCALLN_LINK 0x20270UL
#endif
#ifndef DAGU_KP_UNLOAD_MODULE_DELTA
#define DAGU_KP_UNLOAD_MODULE_DELTA 0x3e00UL
#endif

#ifndef DAGU_KP_UNLOAD_MODULE_PROLOGUE_0
#define DAGU_KP_UNLOAD_MODULE_PROLOGUE_0 0xa9bb7bfdU
#endif
#ifndef DAGU_KP_UNLOAD_MODULE_PROLOGUE_1
#define DAGU_KP_UNLOAD_MODULE_PROLOGUE_1 0x910003fdU
#endif
#ifndef DAGU_KP_UNLOAD_MODULE_PROLOGUE_2
#define DAGU_KP_UNLOAD_MODULE_PROLOGUE_2 0xa9025bf5U
#endif
#ifndef DAGU_KP_UNLOAD_MODULE_PROLOGUE_3
#define DAGU_KP_UNLOAD_MODULE_PROLOGUE_3 0xb4000c00U
#endif

KPM_NAME(DAGU_MODULE_NAME);
KPM_VERSION("0.3.0-dev1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Codex");
KPM_DESCRIPTION("Droidspaces fake PID/IPC namespace behavior for dagu");

static unsigned int unload_guard_installed;
static unsigned int module_initialized;
static void *unload_hook_target;

static int string_equals(const char *left, const char *right)
{
    unsigned int i;
    if (!left || !right)
        return 0;
    for (i = 0; left[i] && right[i]; ++i)
        if (left[i] != right[i])
            return 0;
    return left[i] == right[i];
}

static void before_unload_module(hook_fargs2_t *args, void *unused)
{
    const char *module_name = (const char *)(unsigned long)args->arg0;
    (void)unused;
    if (!string_equals(module_name, DAGU_MODULE_NAME))
        return;

    args->ret = (unsigned long)-DAGU_EBUSY;
    args->skip_origin = 1;
    logki("ds-dagu-v02: blocked unload_module(%s) before KernelPatch unlink/free\n",
          DAGU_MODULE_NAME);
}

/*
 * KernelPatch 0xd03 ignores a KPM exit error after unlinking it and freeing
 * its executable allocation. The device KPImg does not export the newer
 * hook_syscalln_override API, so wrap its pinned unload_module entry directly.
 * Derive the runtime address from the exported hook_syscalln anchor and verify
 * the complete target prologue before patching any KPImg text.
 */
static int install_unload_guard(void)
{
    const unsigned long link_delta = DAGU_KP_UNLOAD_MODULE_DELTA;
    unsigned long anchor = symbol_lookup_name("hook_syscalln");
    unsigned long target;
    volatile const unsigned int *insn;
    hook_err_t hook_rc;

    if (!anchor || anchor > (~0UL - link_delta))
        return -95;
    target = anchor + link_delta;
    insn = (volatile const unsigned int *)target;
    if (insn[0] != DAGU_KP_UNLOAD_MODULE_PROLOGUE_0 ||
        insn[1] != DAGU_KP_UNLOAD_MODULE_PROLOGUE_1 ||
        insn[2] != DAGU_KP_UNLOAD_MODULE_PROLOGUE_2 ||
        insn[3] != DAGU_KP_UNLOAD_MODULE_PROLOGUE_3) {
        logke("ds-dagu-v02: unload_module signature mismatch target=%lx words=%08x/%08x/%08x/%08x\n",
              target, insn[0], insn[1], insn[2], insn[3]);
        return -95;
    }

    unload_hook_target = (void *)target;
    hook_rc = hook_wrap2(unload_hook_target, before_unload_module, 0, 0);
    if (hook_rc != HOOK_NO_ERR) {
        unload_hook_target = 0;
        logke("ds-dagu-v02: unload_module hook install failed target=%lx rc=%d\n",
              target, (int)hook_rc);
        return -(int)hook_rc;
    }

    unload_guard_installed = 1U;
    logki("ds-dagu-v02: unload_module guard installed target=%lx anchor=%lx\n",
          target, anchor);
    return 0;
}

static void partial_cleanup(void)
{
    int rc;
    if (unload_guard_installed) {
        hook_unwrap(unload_hook_target, before_unload_module, 0);
        unload_guard_installed = 0U;
        unload_hook_target = 0;
    }
    dagu_reboot_syscalls_uninstall();
    dagu_clone3_uninstall();
    dagu_devtmpfs_uninstall();
    dagu_mqueue_uninstall();
    dagu_xt_addrtype_uninstall();
    dagu_msg_syscalls_uninstall();
    dagu_sem_syscalls_uninstall();
    dagu_mq_syscalls_uninstall();
    dagu_nat66_uninstall();
    dagu_userns_uninstall();
    dagu_status_bridge_uninstall();
    dagu_proc_bridge_uninstall();
    dagu_proc_root_dedup_uninstall();
    dagu_pid_exit_guard_uninstall();
    rc = dagu_nsproxy_bridge_uninstall();
    if (rc)
        logke("ds-dagu-v02: nsproxy cleanup refused rc=%d\n", rc);
    dagu_proc_mount_refs_uninstall();
    dagu_pid_lifecycle_uninstall();
    dagu_pid_namespace_unbind();
}

static long dagu_v02_init(const char *args, const char *event, void *reserved)
{
    int rc;
    const char *stage = "version";
    (void)args;
    (void)reserved;

    if ((kver & 0xffff00U) != VERSION(4, 19, 0) || kpver != DAGU_KP_VER ||
        !string_equals(event, "pre-kernel-init"))
        return -95;
    if (!kallsyms_lookup_name)
        return -95;

    stage = "usercopy";
    if ((rc = dagu_usercopy_bind()))
        goto fail;
    stage = "ipc namespace";
    if ((rc = dagu_ipc_namespace_bind()))
        goto fail;
    stage = "message core";
    if ((rc = dagu_msg_core_bind()))
        goto fail;
    stage = "semaphore core";
    if ((rc = dagu_sem_core_bind()))
        goto fail;
    stage = "mqueue core";
    if ((rc = dagu_mq_core_bind()))
        goto fail;
    stage = "ipv6 nat";
    if ((rc = dagu_nat66_bind()))
        goto fail;
    stage = "user namespace";
    if ((rc = dagu_userns_bind()))
        goto fail;
    stage = "pid namespace";
    if ((rc = dagu_pid_namespace_bind()))
        goto fail;
    stage = "pid lifecycle";
    if ((rc = dagu_pid_lifecycle_install()))
        goto fail;
    stage = "proc mount references";
    if ((rc = dagu_proc_mount_refs_install()))
        goto fail;
    stage = "nsproxy bridge";
    if ((rc = dagu_nsproxy_bridge_install()))
        goto fail;
    stage = "pid exit guard";
    if ((rc = dagu_pid_exit_guard_install()))
        goto fail;
    stage = "proc bridge";
    if ((rc = dagu_proc_bridge_install(dagu_pid_proc_operations(),
                                       dagu_pid_children_proc_operations(),
                                       dagu_ipc_proc_operations())))
        goto fail;
    stage = "proc root dedup";
    if ((rc = dagu_proc_root_dedup_install()))
        goto fail;
    stage = "proc status namespace lines";
    if ((rc = dagu_status_bridge_install()))
        goto fail;
    stage = "message syscalls";
    if ((rc = dagu_msg_syscalls_install()))
        goto fail;
    stage = "semaphore syscalls";
    if ((rc = dagu_sem_syscalls_install()))
        goto fail;
    stage = "mqueue syscalls";
    if ((rc = dagu_mq_syscalls_install()))
        goto fail;
    stage = "ipv6 nat";
    if ((rc = dagu_nat66_install()))
        goto fail;
    stage = "user namespace";
    if ((rc = dagu_userns_install()))
        goto fail;
    /*
     * This kernel has no sys_clone3, so clone3.c supplies one through
     * _do_fork. Failure is non-fatal: without _do_fork the syscall keeps
     * returning ENOSYS and the rest of the container path is unaffected,
     * so a warning is logged instead of unwinding.
     */
    stage = "clone3 via _do_fork";
    rc = dagu_clone3_install();
    if (rc)
        logkw("ds-dagu-v02: clone3 unavailable rc=%d; leaving ENOSYS\n", rc);
    rc = 0;
    /*
     * The kernel has no devtmpfs type, so mounting -t devtmpfs fails with
     * ENODEV. Registration makes the type available; failure is non-fatal
     * because the rest of the container path does not depend on it.
     */
    stage = "devtmpfs filesystem type";
    rc = dagu_devtmpfs_install();
    if (rc)
        logkw("ds-dagu-v02: devtmpfs type unavailable rc=%d\n", rc);
    rc = 0;
    /*
     * The kernel has no addrtype match, so iptables cannot build the rule
     * dockerd adds to its NAT chain and the daemon exits. Registration is
     * non-fatal: the match is only needed by callers that use it.
     */
    /*
     * The kernel has no mqueue type, so mounting -t mqueue fails with ENODEV
     * and a container runtime cannot set up /dev/mqueue. Registration is
     * non-fatal for the same reason as devtmpfs: the type is only needed by
     * callers that mount it.
     */
    stage = "mqueue filesystem type";
    rc = dagu_mqueue_install();
    if (rc)
        logkw("ds-dagu-v02: mqueue type unavailable rc=%d\n", rc);
    rc = 0;
    stage = "addrtype match";
    rc = dagu_xt_addrtype_install();
    if (rc)
        logkw("ds-dagu-v02: addrtype match unavailable rc=%d\n", rc);
    rc = 0;
    stage = "reboot syscall isolation";
    if ((rc = dagu_reboot_syscalls_install()))
        goto fail;

    stage = "unload_module inline wrap";
    rc = install_unload_guard();
    if (rc)
        goto fail;
    module_initialized = 1U;
    logki("ds-dagu-v02: v0.3.0-dev1 hooks installed on dagu Android 15 / 4.19.157\n");
    return 0;

fail:
    logke("ds-dagu-v02: init failed at %s rc=%d; unwinding hooks\n", stage, rc);
    partial_cleanup();
    return rc;
}

static long dagu_v02_exit(void *reserved)
{
    (void)reserved;
    if (module_initialized) {
        logke("ds-dagu-v02: unexpected unload path reached; KernelPatch 0xd03 ignores exit veto\n");
        return -DAGU_EBUSY;
    }
    partial_cleanup();
    return 0;
}

KPM_INIT(dagu_v02_init);
KPM_EXIT(dagu_v02_exit);
