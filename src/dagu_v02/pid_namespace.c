/* SPDX-License-Identifier: GPL-2.0-only */
/* Draft PID namespace storage for the exact current Image field offsets. */

#include "abi.h"
#include "pid_namespace.h"

#include <asm/current.h>
#include <kallsyms.h>

#define DAGU_IDR_RT_MARKER 0x02000004U
#define DAGU_PIDNS_ADDING 0x80000000U
#define DAGU_PIDNS_MAX_LEVEL 32U
#define DAGU_PIDNS_OBJECT_SIZE 0x100U
#define DAGU_PID_OBJECT_BASE_SIZE 0x60U
#define DAGU_WORK_NO_POOL 0xfffffffe0UL

typedef void *(*kmalloc_fn)(unsigned long, unsigned int);
typedef void (*kfree_fn)(const void *);
typedef void *(*cache_create_fn)(const char *, unsigned long, unsigned long,
                                 unsigned long, void *);
typedef int (*alloc_inum_fn)(unsigned int *);
typedef void (*free_inum_fn)(unsigned int);
typedef void (*idr_destroy_fn)(void *);
typedef void (*release_proc_fn)(void *);
typedef void (*mutex_init_fn)(void *, const char *, void *);
typedef void (*mutex_fn)(void *);
typedef int (*ns_capable_fn)(void *, int);
typedef void *(*active_pid_ns_fn)(void *);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static cache_create_fn cache_create_ptr;
static alloc_inum_fn alloc_inum_ptr;
static free_inum_fn free_inum_ptr;
static idr_destroy_fn idr_destroy_ptr;
static release_proc_fn release_proc_ptr;
static mutex_init_fn mutex_init_ptr;
static mutex_fn mutex_lock_ptr;
static mutex_fn mutex_unlock_ptr;
static ns_capable_fn ns_capable_ptr;
static active_pid_ns_fn active_pid_ns_ptr;
static void *root_pid_ns_ptr;
static void *init_user_ns_ptr;
static unsigned int root_pid_ops_installed;
static void *pid_caches[DAGU_PIDNS_MAX_LEVEL + 1U];
static char cache_names[DAGU_PIDNS_MAX_LEVEL + 1U][20];
static unsigned char cache_mutex[128] __attribute__((aligned(8)));
static unsigned long cache_mutex_key[8];

/* The native free_pid() schedules this embedded work at namespace +0x80.
 * Native get_pid_ns()/put_pid_ns() are no-ops on CONFIG_PID_NS=n, so the
 * KPM's own extra work reference keeps this object resident until unmount.
 */
static void pid_proc_cleanup(void *work)
{
    void *ns = (unsigned char *)work - DAGU_PIDNS_PROC_WORK;
    release_proc_ptr(ns);
    dagu_pid_namespace_put(ns);
}

void *dagu_pid_root(void)
{
    return root_pid_ns_ptr;
}

void dagu_pid_namespace_get(void *ns)
{
    if (ns && ns != root_pid_ns_ptr)
        __atomic_add_fetch((unsigned int *)ns, 1U, __ATOMIC_RELAXED);
}

void dagu_pid_namespace_put(void *ns)
{
    void *parent;
    if (!ns || ns == root_pid_ns_ptr ||
        __atomic_sub_fetch((unsigned int *)ns, 1U, __ATOMIC_ACQ_REL) != 0U)
        return;
    parent = dagu_load_ptr(ns, DAGU_PIDNS_PARENT);
    idr_destroy_ptr((unsigned char *)ns + DAGU_PIDNS_IDR);
    free_inum_ptr(dagu_load_u32(ns, DAGU_PIDNS_INUM));
    kfree_ptr(ns);
    dagu_pid_namespace_put(parent);
}

static void init_work(void *ns)
{
    unsigned char *work = (unsigned char *)ns + DAGU_PIDNS_PROC_WORK;
    dagu_store_ptr(work, 0x00U, (void *)DAGU_WORK_NO_POOL);
    dagu_store_ptr(work, 0x08U, work + 0x08U);
    dagu_store_ptr(work, 0x10U, work + 0x08U);
    dagu_store_ptr(work, 0x18U, (void *)pid_proc_cleanup);
}

static void cache_name(unsigned int level)
{
    char *name = cache_names[level];
    unsigned int n = level + 1U;
    name[0] = 'd'; name[1] = 'a'; name[2] = 'g'; name[3] = 'u';
    name[4] = '_'; name[5] = 'p'; name[6] = 'i'; name[7] = 'd'; name[8] = '_';
    if (n >= 10U) {
        name[9] = (char)('0' + n / 10U);
        name[10] = (char)('0' + n % 10U);
        name[11] = '\0';
    } else {
        name[9] = (char)('0' + n);
        name[10] = '\0';
    }
}

static void *cache_for_level(unsigned int level)
{
    void *cache;
    if (level > DAGU_PIDNS_MAX_LEVEL)
        return 0;
    mutex_lock_ptr(cache_mutex);
    cache = pid_caches[level];
    if (!cache) {
        cache_name(level);
        cache = cache_create_ptr(cache_names[level],
                                 DAGU_PID_OBJECT_BASE_SIZE + 16U * level,
                                 0U, 0U, 0);
        if (cache)
            pid_caches[level] = cache;
    }
    mutex_unlock_ptr(cache_mutex);
    return cache;
}

void *dagu_pid_namespace_create(void *parent, void *user_ns)
{
    unsigned char *ns;
    unsigned int i;
    unsigned int level;
    if (!parent || !kmalloc_ptr || !alloc_inum_ptr)
        return 0;
    if (user_ns && user_ns != init_user_ns_ptr)
        return 0;
    level = dagu_load_u32(parent, DAGU_PIDNS_LEVEL) + 1U;
    if (level > DAGU_PIDNS_MAX_LEVEL)
        return 0;
    ns = (unsigned char *)kmalloc_ptr(DAGU_PIDNS_OBJECT_SIZE, DAGU_GFP_KERNEL);
    if (!ns)
        return 0;
    for (i = 0; i < DAGU_PIDNS_OBJECT_SIZE; ++i)
        ns[i] = 0;
    dagu_store_u32(ns, DAGU_PIDNS_KREF, 1U);
    dagu_store_u32(ns, DAGU_PIDNS_IDR_GFP_MASK, DAGU_IDR_RT_MARKER);
    dagu_store_u32(ns, DAGU_PIDNS_ALLOCATED, DAGU_PIDNS_ADDING);
    dagu_store_u32(ns, DAGU_PIDNS_LEVEL, level);
    dagu_store_ptr(ns, DAGU_PIDNS_PARENT, parent);
    dagu_store_ptr(ns, DAGU_PIDNS_OWNER_USER_NS,
                   user_ns ? user_ns : init_user_ns_ptr);
    dagu_store_ptr(ns, DAGU_PIDNS_CACHE, cache_for_level(level));
    if (!dagu_load_ptr(ns, DAGU_PIDNS_CACHE)) {
        kfree_ptr(ns);
        return 0;
    }
    init_work(ns);
    if (alloc_inum_ptr((unsigned int *)(ns + DAGU_PIDNS_INUM))) {
        kfree_ptr(ns);
        return 0;
    }
    dagu_store_ptr(ns, DAGU_PIDNS_NS_COMMON + 0x08U,
                   (void *)dagu_pid_proc_operations());
    dagu_pid_namespace_get(parent);
    return ns;
}

static void *from_common(struct dagu_ns_common *common)
{
    return (unsigned char *)common - DAGU_PIDNS_NS_COMMON;
}

static struct dagu_ns_common *pid_get(void *task)
{
    void *ns = active_pid_ns_ptr(task);
    if (!ns)
        return 0;
    dagu_pid_namespace_get(ns);
    return (struct dagu_ns_common *)((unsigned char *)ns + DAGU_PIDNS_NS_COMMON);
}

static struct dagu_ns_common *pid_children_get(void *task)
{
    void *proxy = dagu_load_ptr(task, DAGU_TASK_NSPROXY);
    void *ns;
    if (!proxy)
        return 0;
    ns = dagu_load_ptr(proxy, DAGU_NSPROXY_PID_CHILDREN);
    /* Linux exposes pid_for_children as soon as unshare/clone installs it;
     * the first child (and child_reaper) does not exist yet at that point. */
    if (!ns)
        return 0;
    dagu_pid_namespace_get(ns);
    return (struct dagu_ns_common *)((unsigned char *)ns + DAGU_PIDNS_NS_COMMON);
}

static void pid_put(struct dagu_ns_common *common)
{
    dagu_pid_namespace_put(from_common(common));
}

/* Linux 4.19 permits PID setns only to the caller's active namespace or a
 * descendant. Walk the target's parent chain with the verified level field;
 * the bounded level checks also make malformed chains fail closed. */
static int pid_ns_is_descendant_or_same(void *active, void *target)
{
    unsigned int active_level;
    unsigned int target_level;
    unsigned int expected_level;
    void *cursor = target;

    if (!active || !target)
        return 0;
    active_level = dagu_load_u32(active, DAGU_PIDNS_LEVEL);
    target_level = dagu_load_u32(target, DAGU_PIDNS_LEVEL);
    if (active_level > DAGU_PIDNS_MAX_LEVEL ||
        target_level > DAGU_PIDNS_MAX_LEVEL || target_level < active_level)
        return 0;
    if (target_level == active_level)
        return target == active;

    expected_level = target_level;
    while (expected_level > active_level) {
        void *parent = dagu_load_ptr(cursor, DAGU_PIDNS_PARENT);
        if (!parent || dagu_load_u32(parent, DAGU_PIDNS_LEVEL) + 1U !=
                           expected_level)
            return 0;
        cursor = parent;
        --expected_level;
    }
    return cursor == active;
}

static int pid_install(void *nsproxy, struct dagu_ns_common *common)
{
    void *replacement;
    void *active;
    void *old;
    if (!nsproxy || !common)
        return -22;
    replacement = from_common(common);
    if (!ns_capable_ptr(dagu_load_ptr(replacement, DAGU_PIDNS_OWNER_USER_NS), 21) ||
        !ns_capable_ptr(init_user_ns_ptr, 21))
        return -1;
    active = active_pid_ns_ptr(current);
    if (!pid_ns_is_descendant_or_same(active, replacement))
        return -22;
    old = dagu_load_ptr(nsproxy, DAGU_NSPROXY_PID_CHILDREN);
    dagu_pid_namespace_get(replacement);
    dagu_store_ptr(nsproxy, DAGU_NSPROXY_PID_CHILDREN, replacement);
    dagu_pid_namespace_put(old);
    return 0;
}

static void *pid_owner(struct dagu_ns_common *common)
{
    return dagu_load_ptr(from_common(common), DAGU_PIDNS_OWNER_USER_NS);
}

static struct dagu_ns_common *pid_parent(struct dagu_ns_common *common)
{
    void *parent = dagu_load_ptr(from_common(common), DAGU_PIDNS_PARENT);
    if (!parent)
        return 0;
    dagu_pid_namespace_get(parent);
    return (struct dagu_ns_common *)((unsigned char *)parent + DAGU_PIDNS_NS_COMMON);
}

static const struct dagu_proc_ns_operations pid_operations = {
    .name = "pid", .real_ns_name = 0, .type = DAGU_CLONE_NEWPID,
    .get = pid_get, .put = pid_put, .install = pid_install,
    .owner = pid_owner, .get_parent = pid_parent,
};

static const struct dagu_proc_ns_operations pid_children_operations = {
    .name = "pid_for_children", .real_ns_name = "pid",
    .type = DAGU_CLONE_NEWPID,
    .get = pid_children_get, .put = pid_put, .install = pid_install,
    .owner = pid_owner, .get_parent = pid_parent,
};

const struct dagu_proc_ns_operations *dagu_pid_proc_operations(void)
{
    return &pid_operations;
}

const struct dagu_proc_ns_operations *dagu_pid_children_proc_operations(void)
{
    return &pid_children_operations;
}

int dagu_pid_namespace_bind(void)
{
    kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
    kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
    cache_create_ptr = (cache_create_fn)kallsyms_lookup_name("kmem_cache_create");
    alloc_inum_ptr = (alloc_inum_fn)kallsyms_lookup_name("proc_alloc_inum");
    free_inum_ptr = (free_inum_fn)kallsyms_lookup_name("proc_free_inum");
    idr_destroy_ptr = (idr_destroy_fn)kallsyms_lookup_name("idr_destroy");
    release_proc_ptr = (release_proc_fn)kallsyms_lookup_name("pid_ns_release_proc");
    mutex_init_ptr = (mutex_init_fn)kallsyms_lookup_name("__mutex_init");
    mutex_lock_ptr = (mutex_fn)kallsyms_lookup_name("mutex_lock");
    mutex_unlock_ptr = (mutex_fn)kallsyms_lookup_name("mutex_unlock");
    ns_capable_ptr = (ns_capable_fn)kallsyms_lookup_name("ns_capable");
    active_pid_ns_ptr = (active_pid_ns_fn)kallsyms_lookup_name("task_active_pid_ns");
    root_pid_ns_ptr = (void *)kallsyms_lookup_name("init_pid_ns");
    init_user_ns_ptr = (void *)kallsyms_lookup_name("init_user_ns");
    if (!kmalloc_ptr || !kfree_ptr || !cache_create_ptr || !alloc_inum_ptr ||
        !free_inum_ptr || !idr_destroy_ptr || !release_proc_ptr ||
        !mutex_init_ptr || !mutex_lock_ptr || !mutex_unlock_ptr ||
        !ns_capable_ptr || !active_pid_ns_ptr || !root_pid_ns_ptr ||
        !init_user_ns_ptr)
        return -2;
    if (dagu_load_u32(root_pid_ns_ptr, DAGU_PIDNS_LEVEL) != 0U ||
        dagu_load_u32(root_pid_ns_ptr, DAGU_PIDNS_INUM) != 0xeffffffcU ||
        (dagu_load_u32(root_pid_ns_ptr, DAGU_PIDNS_IDR_GFP_MASK) & 4U) != 4U ||
        !dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_CACHE) ||
        dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_PARENT))
        return -22;
    if (dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_NS_COMMON + 0x08U) &&
        dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_NS_COMMON + 0x08U) !=
            &pid_operations)
        return -22;
    /* CONFIG_PID_NS=n leaves init_pid_ns.ns.ops unset. proc_ns_instantiate()
     * still returns this object for /proc/<pid>/ns/pid, and nsfs_evict() calls
     * ns->ops->put when the inode is reclaimed. */
    dagu_store_ptr(root_pid_ns_ptr, DAGU_PIDNS_NS_COMMON + 0x08U,
                   (void *)&pid_operations);
    root_pid_ops_installed = 1U;
    mutex_init_ptr(cache_mutex, "dagu_pid_caches", cache_mutex_key);
    return 0;
}

void dagu_pid_namespace_unbind(void)
{
    if (!root_pid_ops_installed || !root_pid_ns_ptr)
        return;
    if (dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_NS_COMMON + 0x08U) ==
        &pid_operations)
        dagu_store_ptr(root_pid_ns_ptr, DAGU_PIDNS_NS_COMMON + 0x08U, 0);
    root_pid_ops_installed = 0U;
}
