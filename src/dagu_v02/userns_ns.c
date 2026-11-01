/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Namespace file entries for a kernel built without CONFIG_USER_NS.
 *
 * The kernel gates /proc/<pid>/ns/user on the same option, so a task that has
 * a user namespace still has no entry naming it. The directory lookup is
 * re-entered for that one name and the entry is built by the kernel function
 * that builds the other namespace entries; everything after the lookup,
 * including the symlink target and the nsfs inode behind it, is the kernel's
 * own code, driven by the operations table installed here.
 *
 * The install callback hands the transition to the namespace code that owns the
 * records: setns() replaces the calling task's credentials with ones in the
 * target namespace after the target's capability check passes.
 */
#include "abi.h"
#include "userns.h"

#include <hook.h>
#include <kallsyms.h>

/* struct dentry */
#define DENTRY_D_PARENT   0x18U
#define DENTRY_D_NAME     0x20U
#define DENTRY_D_SB       0x68U
#define QSTR_LEN          0x04U
#define QSTR_NAME         0x08U

/* struct ns_common */
#define NS_COMMON_OPS     0x08U
#define NS_COMMON_INUM    0x10U

/* struct user_namespace */
#define UNS_NS            0xf8U
#define UNS_PARENT        0xe0U

/* struct super_block, struct cred, struct task_struct */
#define SB_FS_INFO        0x440U
#define CRED_USER_NS      0x88U
#define TASK_CRED         0x7e8U
#define TASK_USAGE        0x68U

#define CLONE_NEWUSER     0x10000000U
#define PROC_USER_INIT_INO 4026531837U
#define NAME_TO_INT_ERR   0xffffffffU

struct dagu_ns_ops {
    const char *name;
    const char *real_ns_name;
    int type;
    void *get;
    void *put;
    void *install;
    void *owner;
    void *get_parent;
};

static void *(*instantiate_fn)(void *dentry, void *task, const void *ops);
static void *(*find_task_fn)(int nr, void *pid_ns);
static unsigned int (*name_to_int_fn)(const void *name);
static void (*rcu_lock_fn)(void);
static void (*rcu_unlock_fn)(void);
static void (*put_task_fn)(void *task);
static void *init_user_ns_ptr;
static void *lookup_addr;
static unsigned int installed;

static const char user_ns_name[] = "user";

static void *userns_ns_get(void *task)
{
    void *cred = dagu_load_ptr(task, TASK_CRED);

    if (!cred)
        return 0;
    cred = dagu_load_ptr(cred, CRED_USER_NS);
    if (!cred)
        return 0;

    return (char *)cred + UNS_NS;
}

static void userns_ns_put(void *ns)
{
    (void)ns;
}

static long install_target(void *ns);

static long install_target(void *ns)
{
    return dagu_userns_install_ns(ns);
}

static int userns_ns_install(void *nsproxy, void *ns)
{
    (void)nsproxy;
    if (!ns)
        return -22;
    return (int)install_target((char *)ns - UNS_NS);
}

static void *userns_ns_owner(void *ns)
{
    return (char *)ns - UNS_NS;
}

static void *userns_ns_get_parent(void *ns)
{
    void *parent = dagu_load_ptr((char *)ns - UNS_NS, UNS_PARENT);

    return parent ? (char *)parent + UNS_NS : 0;
}

static struct dagu_ns_ops userns_ops = {
    .name = user_ns_name,
    .real_ns_name = user_ns_name,
    .type = (int)CLONE_NEWUSER,
    .get = userns_ns_get,
    .put = userns_ns_put,
    .install = userns_ns_install,
    .owner = userns_ns_owner,
    .get_parent = userns_ns_get_parent,
};

void *dagu_userns_ns_ops(void)
{
    return &userns_ops;
}

/*
 * The lookup runs with the parent directory already resolved, so the task is
 * found the same way the id map files find it: the parent name carries the
 * number and the superblock carries the pid namespace.
 */
static void ns_lookup_after(hook_fargs4_t *args, void *udata)
{
    void *dentry = (void *)args->arg1;
    const char *name;
    void *parent;
    void *sb;
    void *pid_ns;
    void *task;
    void *res;
    unsigned int nr;
    unsigned int len;

    (void)udata;

    if ((long)args->ret != -2)                  /* -ENOENT */
        return;
    if (!dentry)
        return;
    if (!instantiate_fn || !find_task_fn || !name_to_int_fn ||
        !rcu_lock_fn || !rcu_unlock_fn || !put_task_fn)
        return;

    len = dagu_load_u32(dentry, DENTRY_D_NAME + QSTR_LEN);
    name = (const char *)dagu_load_ptr(dentry, DENTRY_D_NAME + QSTR_NAME);
    if (len != 4U || !name)
        return;
    if (name[0] != 'u' || name[1] != 's' || name[2] != 'e' || name[3] != 'r')
        return;

    parent = dagu_load_ptr(dentry, DENTRY_D_PARENT);
    if (!parent)
        return;
    parent = dagu_load_ptr(parent, DENTRY_D_PARENT);
    if (!parent)
        return;
    nr = name_to_int_fn((char *)parent + DENTRY_D_NAME);
    if (nr == NAME_TO_INT_ERR)
        return;

    sb = dagu_load_ptr(dentry, DENTRY_D_SB);
    if (!sb)
        return;
    pid_ns = dagu_load_ptr(sb, SB_FS_INFO);
    if (!pid_ns)
        return;

    task = 0;
    rcu_lock_fn();
    task = find_task_fn((int)nr, pid_ns);
    if (task)
        __atomic_add_fetch((unsigned int *)((char *)task + TASK_USAGE), 1U,
                           __ATOMIC_RELAXED);
    rcu_unlock_fn();
    if (!task)
        return;

    res = instantiate_fn(dentry, task, &userns_ops);
    args->ret = res ? (unsigned long)res : 0UL;

    if (__atomic_sub_fetch((unsigned int *)((char *)task + TASK_USAGE), 1U,
                           __ATOMIC_RELAXED) == 0)
        put_task_fn(task);
}

int dagu_userns_ns_bind(void)
{
    instantiate_fn = (void *(*)(void *, void *, const void *))
        kallsyms_lookup_name("proc_ns_instantiate");
    find_task_fn = (void *(*)(int, void *))
        kallsyms_lookup_name("find_task_by_pid_ns");
    name_to_int_fn = (unsigned int (*)(const void *))
        kallsyms_lookup_name("name_to_int");
    rcu_lock_fn = (void (*)(void))kallsyms_lookup_name("__rcu_read_lock");
    rcu_unlock_fn = (void (*)(void))kallsyms_lookup_name("__rcu_read_unlock");
    put_task_fn = (void (*)(void *))kallsyms_lookup_name("__put_task_struct");
    lookup_addr = (void *)kallsyms_lookup_name("proc_ns_dir_lookup");
    init_user_ns_ptr = (void *)kallsyms_lookup_name("init_user_ns");

    if (!instantiate_fn || !find_task_fn || !name_to_int_fn ||
        !rcu_lock_fn || !rcu_unlock_fn || !put_task_fn || !lookup_addr)
        return -2;

    return 0;
}

int dagu_userns_ns_install(void)
{
    hook_err_t rc;

    if (installed)
        return -22;

    /*
     * The initial namespace has no operations table without the option, so
     * /proc/1/ns/user would name an entry whose backing object has none.
     */
    if (init_user_ns_ptr) {
        dagu_store_ptr((char *)init_user_ns_ptr + UNS_NS, NS_COMMON_OPS,
                       &userns_ops);
        dagu_store_u32((char *)init_user_ns_ptr + UNS_NS, NS_COMMON_INUM,
                       PROC_USER_INIT_INO);
    }

    rc = hook_wrap3(lookup_addr, 0, ns_lookup_after, 0);
    if (rc != HOOK_NO_ERR) {
        logkw("ds-dagu-userns: ns lookup not hooked\n");
        return -1;
    }

    __atomic_store_n(&installed, 1U, __ATOMIC_RELEASE);
    logki("ds-dagu-userns: ns user entry hooked\n");

    return 0;
}

void dagu_userns_ns_uninstall(void)
{
    if (!__atomic_load_n(&installed, __ATOMIC_ACQUIRE))
        return;

    __atomic_store_n(&installed, 0U, __ATOMIC_RELEASE);

    if (lookup_addr)
        hook_unwrap(lookup_addr, 0, ns_lookup_after);
}
