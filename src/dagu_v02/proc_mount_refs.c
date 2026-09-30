/* SPDX-License-Identifier: GPL-2.0-only */
/* Replace the proc superblock PIDNS references compiled out with PID_NS=n. */

#include "abi.h"
#include "pid_namespace.h"
#include "proc_mount_refs.h"

#include <hook.h>
#include <kallsyms.h>

/* Current boot proc_set_super stores s_fs_info at +0x440. */
#define DAGU_SB_FS_INFO 0x440U

static void *set_target;
static void *kill_target;
static unsigned int installed;

static void after_set(hook_fargs2_t *args, void *unused)
{
    void *sb = (void *)args->arg0;
    void *requested = (void *)args->arg1;
    (void)unused;
    if (sb && (long)args->ret == 0L &&
        dagu_load_ptr(sb, DAGU_SB_FS_INFO) == requested)
        dagu_pid_namespace_get(requested);
}

static void before_kill(hook_fargs1_t *args, void *unused)
{
    void *sb = (void *)args->arg0;
    (void)unused;
    args->local.data0 = sb ? (unsigned long)dagu_load_ptr(sb, DAGU_SB_FS_INFO) : 0UL;
}

static void after_kill(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    dagu_pid_namespace_put((void *)args->local.data0);
}

void dagu_proc_mount_refs_uninstall(void)
{
    if (installed & 2U)
        hook_unwrap(kill_target, before_kill, after_kill);
    if (installed & 1U)
        hook_unwrap(set_target, 0, after_set);
    installed = 0;
}

int dagu_proc_mount_refs_install(void)
{
    hook_err_t rc;
    if (installed || !dagu_pid_root())
        return -22;
    set_target = (void *)kallsyms_lookup_name("proc_set_super");
    kill_target = (void *)kallsyms_lookup_name("proc_kill_sb");
    if (!set_target || !kill_target)
        return -2;
    rc = hook_wrap2(set_target, 0, after_set, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    installed = 1U;
    rc = hook_wrap1(kill_target, before_kill, after_kill, 0);
    if (rc != HOOK_NO_ERR) {
        dagu_proc_mount_refs_uninstall();
        return -(int)rc;
    }
    installed = 3U;
    return 0;
}
