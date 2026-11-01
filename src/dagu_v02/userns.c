/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * User namespaces for a kernel built without CONFIG_USER_NS.
 *
 * The kernel compiles the namespace object, its syscall handling and the
 * ownership helpers out: create_user_ns() returns -EINVAL, get_user_ns()
 * returns &init_user_ns whatever it is handed, and current_user_ns() is
 * constant. A namespace is therefore built here, handed to a fresh credential,
 * and the places that would have recorded the host as owner are corrected.
 *
 * The credential carries the full capability set for its own namespace. Checks
 * against the initial namespace then fail on the level comparison, which is
 * what makes the namespace an isolation boundary.
 */
#include "abi.h"
#include "userns.h"

#include <asm/current.h>
#include <hook.h>
#include <kallsyms.h>

#define DAGU_USERNS_MAX 128U

/* struct user_namespace, read from this kernel's debug information */
#define UNS_COUNT       0x0d8U
#define UNS_PARENT      0x0e0U
#define UNS_LEVEL       0x0e8U
#define UNS_OWNER       0x0ecU
#define UNS_GROUP       0x0f0U
#define UNS_NS          0x0f8U
#define UNS_FLAGS       0x110U
#define UNS_UCOUNTS     0x1b0U
#define UNS_UCOUNT_MAX  0x1b8U
#define UNS_SIZE        0x1f0U

/* struct uid_gid_map, three of which start the namespace */
#define UNS_UID_MAP     0x000U
#define UNS_GID_MAP     0x048U
#define UNS_PROJID_MAP  0x090U
#define MAP_NR_EXTENTS  0x00U
#define MAP_EXTENT      0x08U
#define MAP_EXTENT_STEP 0x0cU

#define NS_COMMON_OPS   0x08U
#define NS_COMMON_INUM  0x10U
#define DAGU_USERNS_INUM_BASE 4026531900U

/* struct cred */
#define CRED_SECUREBITS    0x24U
#define CRED_CAP_INH       0x28U
#define CRED_CAP_PERM      0x30U
#define CRED_CAP_EFF       0x38U
#define CRED_CAP_BSET      0x40U
#define CRED_CAP_AMB       0x48U
#define CRED_USER_NS       0x88U

/* struct task_struct */
#define TASK_REAL_CRED 0x7e0U
#define TASK_CRED      0x7e8U
#define TASK_FS        0x808U

/* struct mnt_namespace */
#define MNTNS_USER_NS  0x38U

/* struct super_block */
#define SB_USER_NS     0x4f8U

#define DAGU_CLONE_NEWNS   0x00020000UL
#define DAGU_NS_FLAGS      0x6e020000UL
#define DAGU_CLONE_NEWPID  0x20000000UL
#define NSPROXY_PID_CHILDREN 0x20U
#define PIDNS_USER_NS      0x70U
#define DAGU_CLONE_NEWUSER 0x10000000UL
#define DAGU_CLONE_THREAD  0x00010000UL
#define DAGU_CLONE_FS      0x00000200UL

#define DAGU_ENOMEM   (-12L)
#define DAGU_EINVAL   (-22L)
#define DAGU_CAP_SYS_ADMIN 21

struct dagu_userns {
    unsigned char record[UNS_SIZE];
    void *parent;
    unsigned int level;
    unsigned int refs;
    unsigned int holders;
    unsigned int live;
};

/*
 * Every count is bounded: a runaway holder or reference count means a caller
 * lost track of a record, and letting the counts wrap would release a
 * namespace another credential still points at.
 */
#define DAGU_USERNS_COUNT_MAX (1U << 20)

static int userns_warned;

static void userns_warn(const char *what)
{
    if (userns_warned)
        return;
    userns_warned = 1;
    logki("ds-dagu-userns: %s\n", what);
}

typedef void *(*prepare_creds_fn)(void);
typedef void (*abort_creds_fn)(void *);
typedef int (*commit_creds_fn)(void *);
typedef void *(*create_new_namespaces_fn)(unsigned long, void *, void *, void *);
typedef int (*ns_capable_fn)(void *, int);

static struct dagu_userns pool[DAGU_USERNS_MAX];
static unsigned int pool_lock;
static unsigned int installed;
static unsigned int layout_ok;
static unsigned int live_count;

static void *init_user_ns_ptr;
static void *init_ns_ops_ptr;
static prepare_creds_fn prepare_creds_ptr;
static abort_creds_fn abort_creds_ptr;
static commit_creds_fn commit_creds_ptr;
static create_new_namespaces_fn create_new_namespaces_ptr;
static ns_capable_fn ns_capable_ptr;

static void *ksys_unshare_addr;
static void *copy_creds_addr;
static void *unshare_nsproxy_addr;
static void *inode_cap_addr;
static void *copy_mnt_ns_addr;
static void *sget_userns_addr;
static void *sget_addr;
static void *mount_nodev_addr;
static void *put_cred_addr;
typedef void *(*sget_userns_fn)(void *, void *, void *, int, void *, void *);
static sget_userns_fn sget_userns_ptr;

static unsigned int hook_bits;

/*
 * A combined CLONE_NEWUSER|CLONE_NEWNS call creates the namespace before the
 * new credential is installed, so the namespace the mount copy belongs to is
 * not reachable from current->cred while it is being built. The record is
 * parked here for the length of the syscall instead.
 */
#define PENDING_SLOTS 8U

static struct {
    void *task;
    void *record;
} pending_slots[PENDING_SLOTS];

static void pending_set(void *task, void *record)
{
    unsigned int i;

    for (i = 0; i < PENDING_SLOTS; i++) {
        if (!pending_slots[i].task || pending_slots[i].task == task) {
            pending_slots[i].task = task;
            pending_slots[i].record = record;
            return;
        }
    }
}

static void *pending_get(void *task)
{
    unsigned int i;

    for (i = 0; i < PENDING_SLOTS; i++) {
        if (pending_slots[i].task == task)
            return pending_slots[i].record;
    }

    return 0;
}

static void pending_clear(void *task)
{
    unsigned int i;

    for (i = 0; i < PENDING_SLOTS; i++) {
        if (pending_slots[i].task == task) {
            pending_slots[i].task = 0;
            pending_slots[i].record = 0;
        }
    }
}

static void lock_pool(void)
{
    while (__atomic_exchange_n(&pool_lock, 1U, __ATOMIC_ACQUIRE))
        __asm__ volatile("yield" ::: "memory");
}

static void unlock_pool(void)
{
    __atomic_store_n(&pool_lock, 0U, __ATOMIC_RELEASE);
}

static void *record_of(struct dagu_userns *u)
{
    return u ? u->record : 0;
}

static struct dagu_userns *slot_of_record(void *record);

int dagu_userns_is_record(void *ns)
{
    return ns && slot_of_record(ns) != 0;
}

static struct dagu_userns *slot_of_record(void *record)
{
    unsigned int i;
    for (i = 0; i < DAGU_USERNS_MAX; i++) {
        if (__atomic_load_n(&pool[i].live, __ATOMIC_ACQUIRE) &&
            record_of(&pool[i]) == record)
            return &pool[i];
    }
    return 0;
}

struct dagu_userns *dagu_userns_of_task(void *task)
{
    void *cred = dagu_load_ptr(task, TASK_CRED);
    void *user_ns;
    if (!cred)
        return 0;
    user_ns = dagu_load_ptr(cred, CRED_USER_NS);
    if (!user_ns)
        return 0;
    return slot_of_record(user_ns);
}

/*
 * The maps are the identity: the kernel's own conversion helpers read them to
 * turn a kuid into the id a task sees, and a namespace with no extents would
 * report overflow ids instead.
 */
static void fill_map(unsigned char *record, unsigned int off)
{
    dagu_store_u32(record, off + MAP_NR_EXTENTS, 1U);
    dagu_store_u32(record, off + MAP_EXTENT, 0U);
    dagu_store_u32(record, off + MAP_EXTENT + 4U, 0U);
    dagu_store_u32(record, off + MAP_EXTENT + 8U, 0xffffffffU);
}

static void fill_record(struct dagu_userns *u, void *parent)
{
    unsigned int level = 0;

    level = (parent ? (unsigned int)dagu_load_u32(parent, UNS_LEVEL) : 0U) + 1U;
    fill_map(u->record, UNS_UID_MAP);
    fill_map(u->record, UNS_GID_MAP);
    fill_map(u->record, UNS_PROJID_MAP);
    dagu_store_u32(u->record, UNS_COUNT, 1U);
    dagu_store_ptr(u->record, UNS_PARENT, parent ? parent : init_user_ns_ptr);
    dagu_store_u32(u->record, UNS_LEVEL, level);
    dagu_store_u32(u->record, UNS_OWNER, 0U);
    dagu_store_u32(u->record, UNS_GROUP, 0U);
    /*
     * The namespace file entries print the number behind /proc/<pid>/ns, and
     * the nsfs inode behind the link keeps it, so each record gets its own.
     */
    dagu_store_ptr(u->record, UNS_NS + NS_COMMON_OPS, dagu_userns_ns_ops());
    dagu_store_u32(u->record, UNS_NS + NS_COMMON_INUM,
                   DAGU_USERNS_INUM_BASE + (unsigned int)(u - pool));
    dagu_store_ptr(u->record, UNS_FLAGS, 0);
    /*
     * A namespace without ucounts cannot create mount namespaces, and a zero
     * ucount limit makes the first allocation fail with ENOSPC. Both are taken
     * from the initial namespace.
     */
    dagu_store_ptr(u->record, UNS_UCOUNTS,
                   dagu_load_ptr(init_user_ns_ptr, UNS_UCOUNTS));
    {
        unsigned int n;
        for (n = 0; n < 8U; n++) {
            unsigned int off = UNS_UCOUNT_MAX + n * 8U;
            dagu_store_u32(u->record, off, dagu_load_u32(init_user_ns_ptr, off));
            dagu_store_u32(u->record, off + 4U,
                           dagu_load_u32(init_user_ns_ptr, off + 4U));
        }
    }
    dagu_store_ptr(u->record, UNS_UCOUNT_MAX, 0);
    u->parent = parent;
    u->level = level;
}

static struct dagu_userns *userns_create(void *parent)
{
    struct dagu_userns *u = 0;
    unsigned int i;

    if (!__atomic_load_n(&installed, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&layout_ok, __ATOMIC_ACQUIRE))
        return 0;
    /*
     * Records may nest: a container that already runs in one can create
     * another for a service that asks for its own namespace. The parent
     * pointer is always a live pool slot, never an arbitrary address.
     */
    if (parent && !slot_of_record(record_of((struct dagu_userns *)parent)))
        return 0;

    lock_pool();
    for (i = 0; i < DAGU_USERNS_MAX; i++) {
        if (!__atomic_load_n(&pool[i].live, __ATOMIC_ACQUIRE)) {
            u = &pool[i];
            u->live = 1;
            break;
        }
    }
    unlock_pool();
    if (!u)
        return 0;

    {
        unsigned char *bytes = u->record;
        unsigned int n;
        for (n = 0; n < UNS_SIZE; n++)
            bytes[n] = 0;
    }
    fill_record(u, parent);
    u->refs = 1;
    ++live_count;
    return u;
}

static int userns_get(unsigned int *field)
{
    unsigned int old = __atomic_load_n(field, __ATOMIC_RELAXED);

    for (;;) {
        if (old >= DAGU_USERNS_COUNT_MAX) {
            userns_warn("reference count past its limit");
            return -1;
        }
        if (__atomic_compare_exchange_n(field, &old, old + 1U, 1,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return 0;
    }
}

static int userns_drop(unsigned int *field)
{
    unsigned int old = __atomic_load_n(field, __ATOMIC_RELAXED);

    for (;;) {
        if (old == 0U)
            return -1;
        if (__atomic_compare_exchange_n(field, &old, old - 1U, 1,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return 0;
    }
}

/*
 * The credential is not the only reference: a mount or pid namespace keeps
 * the namespace it was created in, and the kernel releases those through
 * get_user_ns()/put_user_ns(), which this kernel compiles to nothing. Every
 * such holder is counted here instead, so a slot is only reusable once both
 * the credential and the namespaces built from it are gone.
 */
void dagu_userns_hold(void *ns)
{
    struct dagu_userns *u = slot_of_record(ns);

    if (!u)
        return;
    (void)userns_get(&u->holders);
}

static void userns_put(struct dagu_userns *u)
{
    if (!u)
        return;
    if (!__atomic_load_n(&u->live, __ATOMIC_ACQUIRE))
        return;
    if (userns_drop(&u->refs)) {
        userns_warn("record released twice");
        return;
    }
    if (__atomic_load_n(&u->refs, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&u->holders, __ATOMIC_ACQUIRE))
        return;
    u->parent = 0;
    u->level = 0;
    if (live_count)
        --live_count;
    __atomic_store_n(&u->live, 0U, __ATOMIC_RELEASE);
}

unsigned int dagu_userns_live(void)
{
    return live_count;
}

static void set_caps(void *cred, unsigned int offset, unsigned int value)
{
    dagu_store_u32(cred, offset, value);
    dagu_store_u32(cred, offset + 4U, value);
}

static void install_cred(void *cred, struct dagu_userns *u)
{
    dagu_store_u32(cred, CRED_SECUREBITS, 0U);
    set_caps(cred, CRED_CAP_INH, 0U);
    set_caps(cred, CRED_CAP_PERM, 0xffffffffU);
    set_caps(cred, CRED_CAP_EFF, 0xffffffffU);
    set_caps(cred, CRED_CAP_BSET, 0xffffffffU);
    set_caps(cred, CRED_CAP_AMB, 0U);
    dagu_store_ptr(cred, CRED_USER_NS, record_of(u));
}

static long install_current(struct dagu_userns *u)
{
    void *cred;

    if (!prepare_creds_ptr || !commit_creds_ptr)
        return DAGU_EINVAL;
    cred = prepare_creds_ptr();
    if (!cred)
        return DAGU_ENOMEM;
    install_cred(cred, u);
    commit_creds_ptr(cred);
    return 0;
}

static int cap_raised(void *cred, int cap)
{
    unsigned int word;

    if (cap < 0 || cap >= 64)
        return 0;
    word = (unsigned int)dagu_load_u32(cred, CRED_CAP_EFF + (unsigned int)(cap / 32) * 4U);
    return (word >> (cap % 32)) & 1U;
}

/* ksys_unshare(flags) */
static void unshare_before(hook_fargs1_t *args, void *udata)
{
    unsigned long flags = (unsigned long)args->arg0;
    struct dagu_userns *u;
    (void)udata;

    args->local.data0 = 0;
    if (!(flags & DAGU_CLONE_NEWUSER))
        return;
    if (flags & DAGU_CLONE_FS) {
        args->ret = (unsigned long)DAGU_EINVAL;
        args->skip_origin = 1;
        return;
    }
    u = userns_create(slot_of_record(dagu_load_ptr(dagu_load_ptr(current, TASK_CRED), CRED_USER_NS)));
    if (!u) {
        args->ret = (unsigned long)DAGU_ENOMEM;
        args->skip_origin = 1;
        return;
    }
    args->local.data0 = (unsigned long)u;
    pending_set(current, record_of(u));
    args->arg0 = flags & ~DAGU_CLONE_NEWUSER;
}

static void unshare_after(hook_fargs1_t *args, void *udata)
{
    struct dagu_userns *u = (struct dagu_userns *)args->local.data0;
    (void)udata;
    if (!u)
        return;
    pending_clear(current);
    if (args->ret) {
        userns_put(u);
        return;
    }
    install_current(u);
}

/* copy_creds(task, clone_flags) */
static void copy_creds_before(hook_fargs2_t *args, void *udata)
{
    unsigned long flags = (unsigned long)args->arg1;
    struct dagu_userns *u;
    void *parked;
    (void)udata;

    args->local.data0 = 0;
    args->local.data1 = 0;
    /*
     * clone(CLONE_NEWUSER | CLONE_NEWPID) builds the pid namespace before
     * copy_creds runs, so the namespace that will own it has to exist first.
     * clone_before() creates it, parks it here, and drops the flag from the
     * clone call; this hook adopts the parked record instead of making a
     * second one.
     */
    parked = pending_get(current);
    if (parked) {
        u = slot_of_record(parked);
        if (u) {
            args->local.data0 = (unsigned long)u;
            args->local.data1 = 1;
            if (flags & DAGU_CLONE_NEWUSER)
                args->arg1 = flags & ~DAGU_CLONE_NEWUSER;
            return;
        }
    }
    if (!(flags & DAGU_CLONE_NEWUSER) || (flags & DAGU_CLONE_THREAD))
        return;
    u = userns_create(slot_of_record(dagu_load_ptr(dagu_load_ptr(current, TASK_CRED), CRED_USER_NS)));
    if (!u) {
        args->ret = (unsigned long)DAGU_ENOMEM;
        args->skip_origin = 1;
        return;
    }
    args->local.data0 = (unsigned long)u;
    args->arg1 = flags & ~DAGU_CLONE_NEWUSER;
}

static void copy_creds_after(hook_fargs2_t *args, void *udata)
{
    struct dagu_userns *u = (struct dagu_userns *)args->local.data0;
    void *task = (void *)args->arg0;
    void *cred;
    (void)udata;

    if (!u)
        return;
    if (args->local.data1)
        pending_clear(current);
    if (args->ret) {
        userns_put(u);
        return;
    }
    cred = dagu_load_ptr(task, TASK_CRED);
    if (cred)
        install_cred(cred, u);
}

/*
 * Create the namespace a clone(CLONE_NEWUSER | ...) child will live in and
 * park it for copy_creds(). The returned pointer is the record, which the
 * caller uses as the owner of the other namespaces it builds.
 */
int dagu_userns_begin_clone(void **record)
{
    void *cred = dagu_load_ptr(current, TASK_CRED);
    struct dagu_userns *u;

    if (!record)
        return DAGU_EINVAL;
    *record = 0;
    u = userns_create(cred ? slot_of_record(dagu_load_ptr(cred, CRED_USER_NS)) : 0);
    if (!u)
        return DAGU_ENOMEM;
    pending_set(current, record_of(u));
    *record = record_of(u);
    return 0;
}

/* Release a parked record the clone path did not consume. */
void dagu_userns_clone_end(void)
{
    void *parked = pending_get(current);

    if (!parked)
        return;
    pending_clear(current);
    userns_put(slot_of_record(parked));
}

/*
 * setns() on /proc/<pid>/ns/user: the caller must hold CAP_SYS_ADMIN in the
 * target namespace, which for these records means being root in it or in its
 * parent chain.
 */
long dagu_userns_install_ns(void *target)
{
    struct dagu_userns *u = 0;
    void *cred;

    if (!target || !ns_capable_ptr || !prepare_creds_ptr || !commit_creds_ptr)
        return DAGU_EINVAL;
    if (target != init_user_ns_ptr) {
        u = slot_of_record(target);
        if (!u || !__atomic_load_n(&u->live, __ATOMIC_ACQUIRE))
            return DAGU_EINVAL;
    }
    if (!ns_capable_ptr(target, DAGU_CAP_SYS_ADMIN))
        return -1L;

    cred = prepare_creds_ptr();
    if (!cred)
        return DAGU_ENOMEM;
    if (u) {
        if (userns_get(&u->refs)) {
            if (abort_creds_ptr)
                abort_creds_ptr(cred);
            return DAGU_EINVAL;
        }
        install_cred(cred, u);
    } else {
        dagu_store_ptr(cred, CRED_USER_NS, init_user_ns_ptr);
        set_caps(cred, CRED_CAP_PERM, 0xffffffffU);
        set_caps(cred, CRED_CAP_EFF, 0xffffffffU);
    }
    commit_creds_ptr(cred);
    return 0;
}

/* unshare_nsproxy_namespaces(flags, new_nsp, new_cred, new_fs) */
static int ptr_is_err(void *p)
{
    return (unsigned long)p >= (unsigned long)-4095L;
}

static void nsproxy_before(hook_fargs4_t *args, void *udata)
{
    unsigned long flags = (unsigned long)args->arg0;
    void **new_nsp = (void **)args->arg1;
    void *new_cred = (void *)args->arg2;
    void *new_fs = (void *)args->arg3;
    struct dagu_userns *u;
    void *owner;
    void *nsp;
    void *cred;
    (void)udata;

    if (new_cred || !new_nsp)
        return;
    cred = dagu_load_ptr(current, TASK_CRED);
    u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    if (!u)
        u = slot_of_record(pending_get(current));
    if (!u || !(flags & DAGU_NS_FLAGS))
        return;
    if (!cap_raised(cred, DAGU_CAP_SYS_ADMIN))
        return;
    if (!create_new_namespaces_ptr)
        return;
    if (!new_fs)
        new_fs = dagu_load_ptr(current, TASK_FS);
    /*
     * The creation bridge keys the pid and IPC namespaces it builds on this
     * owner, so a pid namespace created here belongs to the new namespace.
     */
    owner = record_of(u);

    nsp = create_new_namespaces_ptr(flags, current, owner, new_fs);
    if (ptr_is_err(nsp)) {
        args->ret = (unsigned long)nsp;
        args->skip_origin = 1;
        return;
    }
    if (flags & DAGU_CLONE_NEWPID) {
        void *pid_ns = dagu_load_ptr(nsp, NSPROXY_PID_CHILDREN);

        if (pid_ns) {
            dagu_store_ptr(pid_ns, PIDNS_USER_NS, record_of(u));
            dagu_userns_hold(record_of(u));
        }
    }
    *new_nsp = nsp;
    args->ret = 0;
    args->skip_origin = 1;
}

/* capable_wrt_inode_uidgid(inode, cap) */
static void inode_cap_before(hook_fargs2_t *args, void *udata)
{
    void *cred;
    struct dagu_userns *u;
    int cap = (int)args->arg1;
    (void)udata;

    cred = dagu_load_ptr(current, TASK_CRED);
    u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    if (!u || !cap_raised(cred, cap))
        return;
    args->ret = 1;
    args->skip_origin = 1;
}

/* copy_mnt_ns(flags, ns, user_ns, new_fs) */
static void copy_mnt_ns_after(hook_fargs4_t *args, void *udata)
{
    void *mnt_ns = (void *)args->ret;
    void *cred;
    struct dagu_userns *u;
    (void)udata;

    if (!mnt_ns || (unsigned long)mnt_ns >= (unsigned long)-4095L)
        return;
    u = slot_of_record((void *)args->arg2);
    if (!u) {
        cred = dagu_load_ptr(current, TASK_CRED);
        u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    }
    if (!u)
        u = slot_of_record(pending_get(current));
    if (!u)
        return;
    dagu_store_ptr(mnt_ns, MNTNS_USER_NS, record_of(u));
    dagu_userns_hold(record_of(u));
}

/*
 * __put_cred() is where a credential stops being used; the namespace it named
 * is released with it. The kernel would call put_user_ns() here, which is a
 * stub in this build, so the reference is dropped from the release path.
 */
static void put_cred_before(hook_fargs1_t *args, void *udata)
{
    void *cred = (void *)args->arg0;
    (void)udata;

    if (!cred)
        return;
    userns_put(slot_of_record(dagu_load_ptr(cred, CRED_USER_NS)));
}

/*
 * sget() takes the requestor's namespace from current_user_ns(), which this
 * kernel compiles to &init_user_ns, so a task in a fake namespace fails its
 * own mount. The check is repeated here against the task's namespace and the
 * call continues in sget_userns() with that owner.
 */
static void sget_before(hook_fargs5_t *args, void *udata)
{
    void *cred = dagu_load_ptr(current, TASK_CRED);
    struct dagu_userns *u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    int flags = (int)args->arg3;
    void *user_ns;
    (void)udata;

    if (!u || !sget_userns_ptr)
        return;
    user_ns = (flags & (1 << 26)) ? init_user_ns_ptr : record_of(u);
    args->ret = (unsigned long)sget_userns_ptr((void *)args->arg0, (void *)args->arg1,
                                               (void *)args->arg2, flags, user_ns,
                                               (void *)args->arg4);
    args->skip_origin = 1;
}

/*
 * mount_nodev() rejects the mount before it allocates a superblock: it asks
 * ns_capable(current_user_ns(), CAP_SYS_ADMIN), and current_user_ns() is the
 * initial namespace by construction on this kernel. The credential is swapped
 * to the initial namespace for the duration of the call so the kernel path
 * runs unchanged, then the superblock is given the namespace that owns it.
 */
static void mount_nodev_before(hook_fargs4_t *args, void *udata)
{
    void *cred = dagu_load_ptr(current, TASK_CRED);
    struct dagu_userns *u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    void *fresh;
    (void)udata;

    args->local.data0 = 0;
    if (!u || !prepare_creds_ptr || !commit_creds_ptr)
        return;
    fresh = prepare_creds_ptr();
    if (!fresh)
        return;
    dagu_store_ptr(fresh, CRED_USER_NS, init_user_ns_ptr);
    commit_creds_ptr(fresh);
    args->local.data0 = (unsigned long)u;
}

static void mount_nodev_after(hook_fargs4_t *args, void *udata)
{
    struct dagu_userns *u = (struct dagu_userns *)args->local.data0;
    void *root = (void *)args->ret;
    void *fresh;
    (void)udata;

    if (!u)
        return;

    if (prepare_creds_ptr && commit_creds_ptr) {
        fresh = prepare_creds_ptr();
        if (fresh) {
            dagu_store_ptr(fresh, CRED_USER_NS, record_of(u));
            commit_creds_ptr(fresh);
        }
    }

    if (root && (unsigned long)root < (unsigned long)-4095L) {
        void *sb = dagu_load_ptr(root, 0x68);          /* dentry->d_sb */
        if (sb)
            dagu_store_ptr(sb, SB_USER_NS, record_of(u));
    }
}

/* sget_userns(type, test, set, user_ns, data) */
static void sget_after(hook_fargs6_t *args, void *udata)
{
    void *sb = (void *)args->ret;
    void *cred;
    struct dagu_userns *u;
    (void)udata;

    if (!sb || (unsigned long)sb >= (unsigned long)-4095L)
        return;
    cred = dagu_load_ptr(current, TASK_CRED);
    u = slot_of_record(dagu_load_ptr(cred, CRED_USER_NS));
    if (!u)
        return;
    if (dagu_load_ptr(sb, SB_USER_NS) == init_user_ns_ptr)
        dagu_store_ptr(sb, SB_USER_NS, record_of(u));
}

static int check_layout(void)
{
    if (!init_user_ns_ptr)
        return DAGU_EINVAL;
    if ((unsigned int)dagu_load_u32(init_user_ns_ptr, UNS_LEVEL) != 0U)
        return DAGU_EINVAL;
    if (dagu_load_ptr(init_user_ns_ptr, UNS_PARENT) != 0)
        return DAGU_EINVAL;
    /*
     * The initial namespace is created by the kernel without the option, so
     * its ns_common carries no operations pointer; userns_ns.c installs one
     * before anything can look the entry up.
     */
    init_ns_ops_ptr = dagu_load_ptr(init_user_ns_ptr, UNS_NS + NS_COMMON_OPS);
    return 0;
}

int dagu_userns_bind(void)
{
    hook_err_t rc;

    init_user_ns_ptr = (void *)kallsyms_lookup_name("init_user_ns");
    prepare_creds_ptr = (prepare_creds_fn)kallsyms_lookup_name("prepare_creds");
    abort_creds_ptr = (abort_creds_fn)kallsyms_lookup_name("abort_creds");
    commit_creds_ptr = (commit_creds_fn)kallsyms_lookup_name("commit_creds");
    create_new_namespaces_ptr =
        (create_new_namespaces_fn)kallsyms_lookup_name("create_new_namespaces");
    ksys_unshare_addr = (void *)kallsyms_lookup_name("ksys_unshare");
    copy_creds_addr = (void *)kallsyms_lookup_name("copy_creds");
    ns_capable_ptr = (ns_capable_fn)kallsyms_lookup_name("ns_capable");
    unshare_nsproxy_addr = (void *)kallsyms_lookup_name("unshare_nsproxy_namespaces");
    inode_cap_addr = (void *)kallsyms_lookup_name("capable_wrt_inode_uidgid");
    copy_mnt_ns_addr = (void *)kallsyms_lookup_name("copy_mnt_ns");
    sget_userns_addr = (void *)kallsyms_lookup_name("sget_userns");
    mount_nodev_addr = (void *)kallsyms_lookup_name("mount_nodev");
    put_cred_addr = (void *)kallsyms_lookup_name("__put_cred");
    sget_addr = (void *)kallsyms_lookup_name("sget");
    sget_userns_ptr = (sget_userns_fn)kallsyms_lookup_name("sget_userns");

    if (!init_user_ns_ptr || !prepare_creds_ptr || !commit_creds_ptr ||
        !create_new_namespaces_ptr)
        return -2;
    if (check_layout()) {
        logke("ds-dagu-userns: layout mismatch level=%u parent=%lx ops=%lx\n",
              dagu_load_u32(init_user_ns_ptr, UNS_LEVEL),
              (unsigned long)dagu_load_ptr(init_user_ns_ptr, UNS_PARENT),
              (unsigned long)dagu_load_ptr(init_user_ns_ptr, UNS_NS + NS_COMMON_OPS));
        return -2;
    }
    __atomic_store_n(&layout_ok, 1U, __ATOMIC_RELEASE);
    rc = dagu_userns_proc_bind();
    if (rc)
        return rc;
    return dagu_userns_ns_bind();
}

int dagu_userns_install(void)
{
    hook_err_t rc;

    if (installed)
        return -22;

    if (ksys_unshare_addr) {
        rc = hook_wrap1(ksys_unshare_addr, unshare_before, unshare_after, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 1U;
    }
    if (copy_creds_addr) {
        rc = hook_wrap2(copy_creds_addr, copy_creds_before, copy_creds_after, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 2U;
    }
    if (unshare_nsproxy_addr) {
        rc = hook_wrap4(unshare_nsproxy_addr, nsproxy_before, 0, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 4U;
    }
    if (inode_cap_addr) {
        rc = hook_wrap2(inode_cap_addr, inode_cap_before, 0, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 8U;
    }
    if (copy_mnt_ns_addr) {
        rc = hook_wrap4(copy_mnt_ns_addr, 0, copy_mnt_ns_after, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 16U;
    }
    if (sget_userns_addr) {
        rc = hook_wrap6(sget_userns_addr, 0, sget_after, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 32U;
    }
    if (sget_addr) {
        rc = hook_wrap5(sget_addr, sget_before, 0, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 256U;
    }
    if (mount_nodev_addr) {
        rc = hook_wrap4(mount_nodev_addr, mount_nodev_before, mount_nodev_after, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 1024U;
    }
    if (put_cred_addr) {
        rc = hook_wrap1(put_cred_addr, put_cred_before, 0, 0);
        if (rc == HOOK_NO_ERR)
            hook_bits |= 2048U;
    }
    if ((hook_bits & 31U) != 31U) {
        logkw("ds-dagu-userns: partial hook set 0x%x\n", hook_bits);
    }
    __atomic_store_n(&installed, 1U, __ATOMIC_RELEASE);
    dagu_userns_proc_install();
    dagu_userns_ns_install();
    logki("ds-dagu-userns: installed, hooks=0x%x\n", hook_bits);
    return 0;
}

void dagu_userns_uninstall(void)
{
    dagu_userns_ns_uninstall();
    dagu_userns_proc_uninstall();
    __atomic_store_n(&installed, 0U, __ATOMIC_RELEASE);
    if (hook_bits & 2048U)
        hook_unwrap(put_cred_addr, put_cred_before, 0);
    if (hook_bits & 32U)
        hook_unwrap(sget_userns_addr, 0, sget_after);
    if (hook_bits & 16U)
        hook_unwrap(copy_mnt_ns_addr, 0, copy_mnt_ns_after);
    if (hook_bits & 8U)
        hook_unwrap(inode_cap_addr, inode_cap_before, 0);
    if (hook_bits & 4U)
        hook_unwrap(unshare_nsproxy_addr, nsproxy_before, 0);
    if (hook_bits & 2U)
        hook_unwrap(copy_creds_addr, copy_creds_before, copy_creds_after);
    if (hook_bits & 1U)
        hook_unwrap(ksys_unshare_addr, unshare_before, unshare_after);
    hook_bits = 0;
}
