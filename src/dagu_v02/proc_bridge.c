/* SPDX-License-Identifier: GPL-2.0-only */
/* VFS bridge for the two namespace entries absent from this kernel build. */

#include "abi.h"
#include "proc_bridge.h"

#include <hook.h>
#include <kallsyms.h>

typedef void *(*get_pid_task_fn)(void *pid, int type);
typedef void (*put_task_struct_fn)(void *task);
typedef void *(*instantiate_fn)(void *dentry, void *task, const void *ops);
typedef int (*fill_cache_fn)(void *file, void *ctx, const char *name,
                             unsigned int len, instantiate_fn instantiate,
                             void *task, const void *ops);

static get_pid_task_fn get_pid_task_ptr;
static put_task_struct_fn put_task_struct_ptr;
static instantiate_fn instantiate_ptr;
static fill_cache_fn fill_cache_ptr;
static void *readdir_target;
static void *lookup_target;
static const void *pid_operations;
static const void *pid_children_operations;
static const void *ipc_operations;
static unsigned int installed;

static void *proc_task_from_inode(const void *inode)
{
    void *pid = *(void *const volatile *)((const unsigned char *)inode - DAGU_PROC_INODE_PID_BACK);
    return get_pid_task_ptr(pid, 0);
}

static void release_task(void *task)
{
    unsigned int *usage = (unsigned int *)((unsigned char *)task + DAGU_TASK_USAGE);
    if (__atomic_sub_fetch(usage, 1U, __ATOMIC_RELEASE) == 0U) {
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        put_task_struct_ptr(task);
    }
}

static int name_equals(const void *dentry, const char *expected, unsigned int length)
{
    const unsigned char *actual = (const unsigned char *)dagu_load_ptr(dentry, DAGU_DENTRY_NAME_PTR);
    unsigned int i;
    if (dagu_load_u32(dentry, DAGU_DENTRY_NAME_LEN) != length || !actual)
        return 0;
    for (i = 0; i < length; ++i)
        if (actual[i] != (unsigned char)expected[i])
            return 0;
    return 1;
}

static void lookup_before(hook_fargs3_t *args, void *unused)
{
    const void *ops = 0;
    void *task;
    (void)unused;
    if (name_equals((void *)args->arg1, "pid", 3U))
        ops = pid_operations;
    else if (name_equals((void *)args->arg1, "pid_for_children", 16U))
        ops = pid_children_operations;
    else if (name_equals((void *)args->arg1, "ipc", 3U))
        ops = ipc_operations;
    if (!ops)
        return;
    task = proc_task_from_inode((void *)args->arg0);
    if (!task)
        return;
    args->ret = (unsigned long)instantiate_ptr((void *)args->arg1, task, ops);
    args->skip_origin = 1;
    release_task(task);
}

static void readdir_after(hook_fargs2_t *args, void *unused)
{
    void *file = (void *)args->arg0;
    void *ctx = (void *)args->arg1;
    void *inode;
    void *task;
    unsigned long long *position;
    (void)unused;
    if ((long)args->ret != 0L || !file || !ctx)
        return;
    inode = dagu_load_ptr(file, DAGU_FILE_INODE);
    if (!inode)
        return;
    position = (unsigned long long *)((unsigned char *)ctx + DAGU_DIR_CONTEXT_POS);
    if (*position < 6ULL || *position > 8ULL)
        return;
    task = proc_task_from_inode(inode);
    if (!task)
        return;
    while (*position <= 8ULL) {
        const char *name;
        unsigned int length;
        const void *ops;
        if (*position == 6ULL) {
            name = "pid";
            length = 3U;
            ops = pid_operations;
        } else if (*position == 7ULL) {
            name = "pid_for_children";
            length = 16U;
            ops = pid_children_operations;
        } else {
            name = "ipc";
            length = 3U;
            ops = ipc_operations;
        }
        if (!fill_cache_ptr(file, ctx, name, length, instantiate_ptr, task, ops))
            break;
        ++*position;
    }
    release_task(task);
}

void dagu_proc_bridge_uninstall(void)
{
    if (installed & 2U)
        hook_unwrap(lookup_target, lookup_before, 0);
    if (installed & 1U)
        hook_unwrap(readdir_target, 0, readdir_after);
    installed = 0;
}

int dagu_proc_bridge_install(const void *pid_ops, const void *pid_children_ops,
                             const void *ipc_ops)
{
    hook_err_t rc;
    if (!pid_ops || !pid_children_ops || !ipc_ops || installed)
        return -22;
    get_pid_task_ptr = (get_pid_task_fn)kallsyms_lookup_name("get_pid_task");
    put_task_struct_ptr = (put_task_struct_fn)kallsyms_lookup_name("__put_task_struct");
    instantiate_ptr = (instantiate_fn)kallsyms_lookup_name("proc_ns_instantiate");
    fill_cache_ptr = (fill_cache_fn)kallsyms_lookup_name("proc_fill_cache");
    readdir_target = (void *)kallsyms_lookup_name("proc_ns_dir_readdir");
    lookup_target = (void *)kallsyms_lookup_name("proc_ns_dir_lookup");
    if (!get_pid_task_ptr || !put_task_struct_ptr || !instantiate_ptr ||
        !fill_cache_ptr || !readdir_target || !lookup_target)
        return -2;
    pid_operations = pid_ops;
    pid_children_operations = pid_children_ops;
    ipc_operations = ipc_ops;
    rc = hook_wrap2(readdir_target, 0, readdir_after, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    installed |= 1U;
    rc = hook_wrap3(lookup_target, lookup_before, 0, 0);
    if (rc != HOOK_NO_ERR) {
        dagu_proc_bridge_uninstall();
        return -(int)rc;
    }
    installed |= 2U;
    return 0;
}
