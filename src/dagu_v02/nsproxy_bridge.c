/* SPDX-License-Identifier: GPL-2.0-only */
/* PID/IPC namespace proxy lifecycle, including clone inheritance. */

#include "abi.h"
#include "ipc_namespace.h"
#include "nsproxy_bridge.h"
#include "ns_types.h"
#include "pid_namespace.h"

#include <asm/current.h>
#include <hook.h>
#include <kallsyms.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#define TRACKED_NSPROXY_COUNT 2048U
#define DAGU_ENOMEM 12L
#define DAGU_EPERM 1L
#define DAGU_EINVAL 22L
#define DAGU_EOPNOTSUPP 95L
#define DAGU_CAP_SYS_ADMIN 21
#define DAGU_CLONE_THREAD 0x00010000UL
#define DAGU_CLONE_SYSVSEM 0x00040000UL
#define DAGU_CLONE_NEWUSER 0x10000000UL
#define DAGU_CLONE_CONTEXT_MAGIC 0x44534743UL

static void *tracked_nsproxies[TRACKED_NSPROXY_COUNT];
static void *init_nsproxy_ptr;
static void *init_pid_ns_ptr;
static void *init_user_ns_ptr;
static void *create_target;
static void *free_target;
static void *(*active_pid_ns_ptr)(void *);
static void (*switch_task_namespaces_ptr)(void *, void *);
static int (*ns_capable_ptr)(void *, int);
static unsigned int installed;

_Static_assert(__NR_clone == 220, "ARM64 clone syscall number changed");

static int remember_nsproxy(void *nsproxy)
{
    unsigned int i;
    for (i = 0; i < TRACKED_NSPROXY_COUNT; ++i) {
        void *empty = 0;
        if (__atomic_compare_exchange_n(&tracked_nsproxies[i], &empty, nsproxy,
                                        0, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
            return 0;
    }
    return -12;
}

static int forget_nsproxy(void *nsproxy)
{
    unsigned int i;
    for (i = 0; i < TRACKED_NSPROXY_COUNT; ++i) {
        void *expected = nsproxy;
        if (__atomic_compare_exchange_n(&tracked_nsproxies[i], &expected, 0,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return 1;
    }
    return 0;
}

static int any_tracked(void)
{
    unsigned int i;
    for (i = 0; i < TRACKED_NSPROXY_COUNT; ++i)
        if (__atomic_load_n(&tracked_nsproxies[i], __ATOMIC_ACQUIRE))
            return 1;
    return 0;
}

static void free_before(hook_fargs1_t *args, void *unused)
{
    void *nsproxy = (void *)args->arg0;
    (void)unused;
    if (nsproxy && forget_nsproxy(nsproxy)) {
        struct dagu_ipc_namespace *ipc =
            (struct dagu_ipc_namespace *)dagu_load_ptr(nsproxy, DAGU_NSPROXY_IPC);
        dagu_ipc_namespace_put(ipc);
        dagu_pid_namespace_put(dagu_load_ptr(nsproxy, DAGU_NSPROXY_PID_CHILDREN));
    }
}

static void create_before(hook_fargs4_t *args, void *unused)
{
    unsigned long flags = (unsigned long)args->arg0;
    struct dagu_ipc_namespace *created = 0;
    void *created_pid = 0;
    void *task = (void *)args->arg1;
    void *parent_pid;
    (void)unused;
    args->local.data0 = 0;
    args->local.data1 = flags;
    args->local.data2 = 0;
    if (flags & (DAGU_CLONE_NEWIPC | DAGU_CLONE_NEWPID)) {
        void *user_ns = (void *)args->arg2;
        if (flags & DAGU_CLONE_NEWUSER) {
            args->ret = (unsigned long)-DAGU_EOPNOTSUPP;
            args->skip_origin = 1;
            return;
        }
        if (!user_ns || user_ns != init_user_ns_ptr ||
            !ns_capable_ptr(user_ns, DAGU_CAP_SYS_ADMIN)) {
            args->ret = (unsigned long)-DAGU_EPERM;
            args->skip_origin = 1;
            return;
        }
    }
    if (flags & DAGU_CLONE_NEWIPC) {
        created = dagu_ipc_namespace_create((void *)args->arg2);
        if (!created) {
            args->ret = (unsigned long)-DAGU_ENOMEM;
            args->skip_origin = 1;
            return;
        }
        args->local.data0 = (unsigned long)created;
    }
    if (flags & DAGU_CLONE_NEWPID) {
        void *old_proxy = dagu_load_ptr(task, DAGU_TASK_NSPROXY);
        parent_pid = old_proxy ? dagu_load_ptr(old_proxy, DAGU_NSPROXY_PID_CHILDREN) : 0;
        if (!parent_pid || active_pid_ns_ptr(task) != parent_pid) {
            dagu_ipc_namespace_put(created);
            args->local.data0 = 0;
            args->ret = (unsigned long)-22L;
            args->skip_origin = 1;
            return;
        }
        created_pid = dagu_pid_namespace_create(parent_pid, (void *)args->arg2);
        if (!created_pid) {
            dagu_ipc_namespace_put(created);
            args->local.data0 = 0;
            args->ret = (unsigned long)-DAGU_ENOMEM;
            args->skip_origin = 1;
            return;
        }
        args->local.data2 = (unsigned long)created_pid;
    }
    args->arg0 = flags & ~(DAGU_CLONE_NEWIPC | DAGU_CLONE_NEWPID);
}

static void create_after(hook_fargs4_t *args, void *unused)
{
    unsigned long flags = (unsigned long)args->local.data1;
    struct dagu_ipc_namespace *created = (struct dagu_ipc_namespace *)args->local.data0;
    void *created_pid = (void *)args->local.data2;
    struct dagu_ipc_namespace *ipc;
    void *pid_ns;
    void *new_nsproxy = (void *)args->ret;
    (void)unused;
    if (!new_nsproxy ||
        (unsigned long)new_nsproxy >= (unsigned long)-4095L) {
        dagu_ipc_namespace_put(created);
        dagu_pid_namespace_put(created_pid);
        return;
    }
    if (flags & DAGU_CLONE_NEWIPC) {
        ipc = created;
        dagu_store_ptr(new_nsproxy, DAGU_NSPROXY_IPC, ipc);
    } else {
        ipc = (struct dagu_ipc_namespace *)dagu_load_ptr(new_nsproxy, DAGU_NSPROXY_IPC);
        dagu_ipc_namespace_get(ipc);
    }
    if (flags & DAGU_CLONE_NEWPID) {
        pid_ns = created_pid;
        dagu_store_ptr(new_nsproxy, DAGU_NSPROXY_PID_CHILDREN, pid_ns);
    } else {
        pid_ns = dagu_load_ptr(new_nsproxy, DAGU_NSPROXY_PID_CHILDREN);
        dagu_pid_namespace_get(pid_ns);
    }
    if (remember_nsproxy(new_nsproxy)) {
        dagu_ipc_namespace_put(ipc);
        dagu_pid_namespace_put(pid_ns);
        dagu_store_ptr(new_nsproxy, DAGU_NSPROXY_IPC, dagu_ipc_root());
        dagu_store_ptr(new_nsproxy, DAGU_NSPROXY_PID_CHILDREN, dagu_pid_root());
        ((void (*)(void *))free_target)(new_nsproxy);
        args->ret = (unsigned long)-DAGU_ENOMEM;
    }
}

static void clone_fail(hook_fargs5_t *args, long error)
{
    args->ret = (unsigned long)-error;
    args->skip_origin = 1;
}

static void *create_private_nsproxy(void)
{
    void *nsproxy = ((void *(*)(unsigned long, void *, void *, void *))
                     create_target)(0UL, current, init_user_ns_ptr, 0);
    if (!nsproxy || (unsigned long)nsproxy >= (unsigned long)-4095L)
        return 0;
    return nsproxy;
}

static void align_proxy_namespace_refs(void *target, void *source)
{
    struct dagu_ipc_namespace *target_ipc;
    struct dagu_ipc_namespace *source_ipc;
    void *target_pid;
    void *source_pid;

    target_ipc = (struct dagu_ipc_namespace *)dagu_load_ptr(target, DAGU_NSPROXY_IPC);
    source_ipc = (struct dagu_ipc_namespace *)dagu_load_ptr(source, DAGU_NSPROXY_IPC);
    if (target_ipc != source_ipc) {
        dagu_ipc_namespace_get(source_ipc);
        dagu_store_ptr(target, DAGU_NSPROXY_IPC, source_ipc);
        dagu_ipc_namespace_put(target_ipc);
    }

    target_pid = dagu_load_ptr(target, DAGU_NSPROXY_PID_CHILDREN);
    source_pid = dagu_load_ptr(source, DAGU_NSPROXY_PID_CHILDREN);
    if (target_pid != source_pid) {
        dagu_pid_namespace_get(source_pid);
        dagu_store_ptr(target, DAGU_NSPROXY_PID_CHILDREN, source_pid);
        dagu_pid_namespace_put(target_pid);
    }
}

/*
 * CONFIG_PID_NS=n makes native clone reject CLONE_NEWPID. Prepare fake
 * namespaces on a private proxy before the original clone. With the namespace
 * bits removed, copy_namespaces() shares that proxy with the child; the
 * parent's after-callback switches to a second proxy holding its old objects.
 */
static void clone_before(hook_fargs5_t *args, void *unused)
{
    unsigned long flags = (unsigned long)syscall_argn(args, 0);
    void *old_proxy;
    void *parent_pid = 0;
    void *fake_pid = 0;
    struct dagu_ipc_namespace *fake_ipc = 0;
    void *restore_proxy = 0;
    void *child_proxy = 0;
    unsigned long namespace_flags = DAGU_CLONE_NEWIPC | DAGU_CLONE_NEWPID;
    int want_pid = (flags & DAGU_CLONE_NEWPID) != 0;
    int want_ipc = (flags & DAGU_CLONE_NEWIPC) != 0;
    (void)unused;

    args->local.data0 = 0;
    args->local.data1 = 0;
    args->local.data2 = 0;
    if (!(flags & namespace_flags))
        return;

    if (((flags & DAGU_CLONE_THREAD) &&
         (flags & (DAGU_CLONE_NEWUSER | DAGU_CLONE_NEWPID))) ||
        ((flags & (DAGU_CLONE_NEWIPC | DAGU_CLONE_SYSVSEM)) ==
         (DAGU_CLONE_NEWIPC | DAGU_CLONE_SYSVSEM))) {
        clone_fail(args, DAGU_EINVAL);
        return;
    }
    if (flags & DAGU_CLONE_NEWUSER) {
        clone_fail(args, DAGU_EOPNOTSUPP);
        return;
    }
    if (!init_user_ns_ptr || !ns_capable_ptr(init_user_ns_ptr, DAGU_CAP_SYS_ADMIN)) {
        clone_fail(args, DAGU_EPERM);
        return;
    }

    old_proxy = dagu_load_ptr(current, DAGU_TASK_NSPROXY);
    if (!old_proxy) {
        clone_fail(args, DAGU_EINVAL);
        return;
    }
    if (want_pid) {
        parent_pid = dagu_load_ptr(old_proxy, DAGU_NSPROXY_PID_CHILDREN);
        if (!parent_pid || active_pid_ns_ptr(current) != parent_pid) {
            clone_fail(args, DAGU_EINVAL);
            return;
        }
        fake_pid = dagu_pid_namespace_create(parent_pid, init_user_ns_ptr);
        if (!fake_pid) {
            clone_fail(args, DAGU_ENOMEM);
            return;
        }
    }
    if (want_ipc) {
        fake_ipc = dagu_ipc_namespace_create(init_user_ns_ptr);
        if (!fake_ipc) {
            dagu_pid_namespace_put(fake_pid);
            clone_fail(args, DAGU_ENOMEM);
            return;
        }
    }

    restore_proxy = create_private_nsproxy();
    if (!restore_proxy)
        goto no_memory;
    child_proxy = create_private_nsproxy();
    if (!child_proxy)
        goto no_memory;

    /* create_new_namespaces(flags=0) keys PID state from the active namespace
     * on this kernel. Preserve the parent's pid_for_children and IPC choices. */
    align_proxy_namespace_refs(restore_proxy, old_proxy);
    align_proxy_namespace_refs(child_proxy, old_proxy);

    if (want_pid) {
        void *old = dagu_load_ptr(child_proxy, DAGU_NSPROXY_PID_CHILDREN);
        dagu_store_ptr(child_proxy, DAGU_NSPROXY_PID_CHILDREN, fake_pid);
        dagu_pid_namespace_put(old);
        fake_pid = 0;
    }
    if (want_ipc) {
        struct dagu_ipc_namespace *old =
            (struct dagu_ipc_namespace *)dagu_load_ptr(child_proxy, DAGU_NSPROXY_IPC);
        dagu_store_ptr(child_proxy, DAGU_NSPROXY_IPC, fake_ipc);
        dagu_ipc_namespace_put(old);
        fake_ipc = 0;
    }

    args->local.data0 = (unsigned long)restore_proxy;
    args->local.data1 = (unsigned long)current;
    args->local.data2 = DAGU_CLONE_CONTEXT_MAGIC;
    switch_task_namespaces_ptr(current, child_proxy);
    set_syscall_argn(args, 0, flags & ~namespace_flags);
    return;

no_memory:
    if (child_proxy)
        ((void (*)(void *))free_target)(child_proxy);
    if (restore_proxy)
        ((void (*)(void *))free_target)(restore_proxy);
    dagu_ipc_namespace_put(fake_ipc);
    dagu_pid_namespace_put(fake_pid);
    clone_fail(args, DAGU_ENOMEM);
}

static void clone_after(hook_fargs5_t *args, void *unused)
{
    void *restore_proxy;
    void *parent_task;
    (void)unused;
    if (args->local.data2 != DAGU_CLONE_CONTEXT_MAGIC)
        return;
    parent_task = (void *)args->local.data1;
    /* The syscall hook can also observe the fork child's return path. */
    if (current != parent_task)
        return;
    restore_proxy = (void *)args->local.data0;
    args->local.data0 = 0;
    args->local.data1 = 0;
    args->local.data2 = 0;
    switch_task_namespaces_ptr(parent_task, restore_proxy);
}

int dagu_nsproxy_bridge_install(void)
{
    hook_err_t rc;
    if (installed)
        return -22;
    init_nsproxy_ptr = (void *)kallsyms_lookup_name("init_nsproxy");
    init_pid_ns_ptr = (void *)kallsyms_lookup_name("init_pid_ns");
    create_target = (void *)kallsyms_lookup_name("create_new_namespaces");
    free_target = (void *)kallsyms_lookup_name("free_nsproxy");
    active_pid_ns_ptr = (void *(*)(void *))kallsyms_lookup_name("task_active_pid_ns");
    switch_task_namespaces_ptr =
        (void (*)(void *, void *))kallsyms_lookup_name("switch_task_namespaces");
    ns_capable_ptr = (int (*)(void *, int))kallsyms_lookup_name("ns_capable");
    init_user_ns_ptr = (void *)kallsyms_lookup_name("init_user_ns");
    if (!init_nsproxy_ptr || !init_pid_ns_ptr || !create_target ||
        !free_target || !active_pid_ns_ptr || !switch_task_namespaces_ptr ||
        !ns_capable_ptr ||
        !init_user_ns_ptr || dagu_pid_root() != init_pid_ns_ptr)
        return -2;
    if (dagu_load_ptr(init_nsproxy_ptr, DAGU_NSPROXY_IPC) != 0 ||
        dagu_load_ptr(init_nsproxy_ptr, DAGU_NSPROXY_PID_CHILDREN) != init_pid_ns_ptr ||
        dagu_load_u32(init_pid_ns_ptr, DAGU_PIDNS_LEVEL) != 0U ||
        dagu_load_u32(init_pid_ns_ptr, DAGU_PIDNS_INUM) != 0xeffffffcU)
        return -22;
    dagu_store_ptr(init_nsproxy_ptr, DAGU_NSPROXY_IPC, dagu_ipc_root());
    rc = hook_wrap1(free_target, free_before, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 1U;
    rc = hook_wrap4(create_target, create_before, create_after, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 2U;
    rc = fp_hook_syscalln(__NR_clone, 5, clone_before, clone_after, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 4U;
    return 0;
fail:
    if (installed & 4U)
        fp_unhook_syscalln(__NR_clone, clone_before, clone_after);
    if (installed & 2U)
        hook_unwrap(create_target, create_before, create_after);
    if (installed & 1U)
        hook_unwrap(free_target, free_before, 0);
    installed = 0;
    dagu_store_ptr(init_nsproxy_ptr, DAGU_NSPROXY_IPC, 0);
    return -(int)rc;
}

int dagu_nsproxy_bridge_uninstall(void)
{
    if (!installed)
        return 0;
    if (any_tracked())
        return -16;
    if (installed & 4U)
        fp_unhook_syscalln(__NR_clone, clone_before, clone_after);
    if (installed & 2U)
        hook_unwrap(create_target, create_before, create_after);
    if (installed & 1U)
        hook_unwrap(free_target, free_before, 0);
    dagu_store_ptr(init_nsproxy_ptr, DAGU_NSPROXY_IPC, 0);
    installed = 0;
    return 0;
}
