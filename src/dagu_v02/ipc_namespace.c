/* SPDX-License-Identifier: GPL-2.0-only */
/* Refcounted IPC namespace identity. SysV object storage is not wired yet. */

#include "abi.h"
#include "ipc_namespace.h"
#include "ipc_namespace_internal.h"

#include <kallsyms.h>

#define DAGU_IPC_INIT_INUM 0xefffffffU

typedef void *(*kmalloc_fn)(unsigned long size, unsigned int flags);
typedef void (*kfree_fn)(const void *pointer);
typedef int (*alloc_inum_fn)(unsigned int *inum);
typedef void (*free_inum_fn)(unsigned int inum);
typedef int (*ns_capable_fn)(void *user_ns, int capability);
typedef void (*mutex_init_fn)(void *lock, const char *name, void *key);
typedef void (*mutex_lock_fn)(void *lock);
typedef void (*mutex_unlock_fn)(void *lock);

static struct dagu_ipc_namespace root_ipc_ns;
static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static alloc_inum_fn alloc_inum_ptr;
static free_inum_fn free_inum_ptr;
static ns_capable_fn ns_capable_ptr;
static mutex_init_fn mutex_init_ptr;
static mutex_lock_fn mutex_lock_ptr;
static mutex_unlock_fn mutex_unlock_ptr;
static void *init_user_ns_ptr;
static unsigned long mutex_lock_class_key[8];

void dagu_ipc_namespace_lock(struct dagu_ipc_namespace *ns)
{
    mutex_lock_ptr(ns->queue_lock);
}

void dagu_ipc_namespace_unlock(struct dagu_ipc_namespace *ns)
{
    mutex_unlock_ptr(ns->queue_lock);
}

int dagu_ipc_namespace_admin(struct dagu_ipc_namespace *ns)
{
    return ns_capable_ptr && ns && ns_capable_ptr(ns->owner_user_ns, 21);
}

static struct dagu_ipc_namespace *from_common(struct dagu_ns_common *common)
{
    return (struct dagu_ipc_namespace *)((unsigned char *)common -
                                         __builtin_offsetof(struct dagu_ipc_namespace, common));
}

void dagu_ipc_namespace_get(struct dagu_ipc_namespace *ns)
{
    if (ns && ns != &root_ipc_ns)
        __atomic_add_fetch(&ns->refs, 1U, __ATOMIC_RELAXED);
}

void dagu_ipc_namespace_put(struct dagu_ipc_namespace *ns)
{
    if (ns && ns != &root_ipc_ns &&
        __atomic_sub_fetch(&ns->refs, 1U, __ATOMIC_ACQ_REL) == 0U) {
        dagu_msg_destroy_all(ns);
        dagu_sem_destroy_all(ns);
        dagu_mq_destroy_all(ns);
        free_inum_ptr(ns->common.inum);
        kfree_ptr(ns);
    }
}

static struct dagu_ns_common *ipc_get(void *task)
{
    void *nsproxy = dagu_load_ptr(task, DAGU_TASK_NSPROXY);
    struct dagu_ipc_namespace *ns;
    if (!nsproxy)
        return 0;
    ns = (struct dagu_ipc_namespace *)dagu_load_ptr(nsproxy, DAGU_NSPROXY_IPC);
    if (!ns)
        return 0;
    dagu_ipc_namespace_get(ns);
    return &ns->common;
}

static void ipc_put(struct dagu_ns_common *common)
{
    dagu_ipc_namespace_put(from_common(common));
}

static int ipc_install(void *nsproxy, struct dagu_ns_common *common)
{
    struct dagu_ipc_namespace *old;
    struct dagu_ipc_namespace *replacement;
    if (!nsproxy || !common)
        return -22;
    replacement = from_common(common);
    if (!ns_capable_ptr || !ns_capable_ptr(replacement->owner_user_ns, 21) ||
        !ns_capable_ptr(init_user_ns_ptr, 21))
        return -1;
    old = (struct dagu_ipc_namespace *)dagu_load_ptr(nsproxy, DAGU_NSPROXY_IPC);
    dagu_ipc_namespace_get(replacement);
    dagu_store_ptr(nsproxy, DAGU_NSPROXY_IPC, replacement);
    dagu_ipc_namespace_put(old);
    return 0;
}

static void *ipc_owner(struct dagu_ns_common *common)
{
    return from_common(common)->owner_user_ns;
}

static const struct dagu_proc_ns_operations ipc_operations = {
    .name = "ipc",
    .real_ns_name = 0,
    .type = DAGU_CLONE_NEWIPC,
    .padding = 0,
    .get = ipc_get,
    .put = ipc_put,
    .install = ipc_install,
    .owner = ipc_owner,
    .get_parent = 0,
};

int dagu_ipc_namespace_bind(void)
{
    kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
    kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
    alloc_inum_ptr = (alloc_inum_fn)kallsyms_lookup_name("proc_alloc_inum");
    free_inum_ptr = (free_inum_fn)kallsyms_lookup_name("proc_free_inum");
    ns_capable_ptr = (ns_capable_fn)kallsyms_lookup_name("ns_capable");
    mutex_init_ptr = (mutex_init_fn)kallsyms_lookup_name("__mutex_init");
    mutex_lock_ptr = (mutex_lock_fn)kallsyms_lookup_name("mutex_lock");
    mutex_unlock_ptr = (mutex_unlock_fn)kallsyms_lookup_name("mutex_unlock");
    init_user_ns_ptr = (void *)kallsyms_lookup_name("init_user_ns");
    if (!kmalloc_ptr || !kfree_ptr || !alloc_inum_ptr || !free_inum_ptr ||
        !ns_capable_ptr || !mutex_init_ptr || !mutex_lock_ptr ||
        !mutex_unlock_ptr || !init_user_ns_ptr)
        return -2;
    root_ipc_ns.refs = 0xffffffffU;
    root_ipc_ns.common.stashed = 0;
    root_ipc_ns.common.ops = &ipc_operations;
    root_ipc_ns.common.inum = DAGU_IPC_INIT_INUM;
    root_ipc_ns.owner_user_ns = init_user_ns_ptr;
    mutex_init_ptr(root_ipc_ns.queue_lock, "dagu_ipc_root", mutex_lock_class_key);
    root_ipc_ns.queues = 0;
    root_ipc_ns.next_queue_id = 1U;
    root_ipc_ns.semaphores = 0;
    root_ipc_ns.next_sem_id = 1U;
    return 0;
}

struct dagu_ipc_namespace *dagu_ipc_root(void)
{
    return &root_ipc_ns;
}

struct dagu_ipc_namespace *dagu_ipc_namespace_create(void *owner_user_ns)
{
    struct dagu_ipc_namespace *ns;
    unsigned int i;
    if (!kmalloc_ptr || !alloc_inum_ptr)
        return 0;
    ns = (struct dagu_ipc_namespace *)kmalloc_ptr(sizeof(*ns), DAGU_GFP_KERNEL);
    if (!ns)
        return 0;
    for (i = 0; i < sizeof(*ns); ++i)
        ((unsigned char *)ns)[i] = 0;
    ns->refs = 1U;
    ns->common.ops = &ipc_operations;
    ns->owner_user_ns = owner_user_ns ? owner_user_ns : init_user_ns_ptr;
    mutex_init_ptr(ns->queue_lock, "dagu_ipc_child", mutex_lock_class_key);
    ns->next_queue_id = 1U;
    ns->semaphores = 0;
    ns->next_sem_id = 1U;
    if (alloc_inum_ptr(&ns->common.inum)) {
        kfree_ptr(ns);
        return 0;
    }
    return ns;
}

const struct dagu_proc_ns_operations *dagu_ipc_proc_operations(void)
{
    return &ipc_operations;
}
