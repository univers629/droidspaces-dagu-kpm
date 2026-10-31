/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Per task id map files for a kernel built without CONFIG_USER_NS.
 *
 * The pid directory entries that expose a task's maps are gated by the same
 * option, so they are absent even though this module creates the namespaces
 * they describe. The two pid lookup functions are re-entered for the three
 * names; a name the kernel rejects gets an inode built from the same
 * primitives the kernel uses for its own entries under /proc/<pid>.
 *
 * Only the identity map is representable: the id map files exist to report it,
 * and a write asking for another mapping is refused rather than accepted and
 * ignored, because nothing in the kernel would ever apply it.
 */
#include "abi.h"
#include "userns.h"

#include <hook.h>
#include <kallsyms.h>

/* struct dentry, struct qstr, struct inode, struct super_block */
#define DENTRY_D_PARENT  0x18U
#define DENTRY_D_NAME    0x20U
#define DENTRY_D_SB      0x68U
#define QSTR_LEN         0x04U
#define QSTR_NAME        0x08U
#define INODE_I_FOP      0x170U
#define INODE_I_PRIVATE  0x288U
#define SB_FS_INFO       0x440U

/* struct user_namespace */
#define UNS_FLAGS        0x110U
#define SETGROUPS_ALLOWED 0x1U

/* struct file */
#define FILE_F_INODE     0x20U

/* struct task_struct, struct cred */
#define TASK_USAGE       0x68U
#define TASK_CRED        0x7e8U
#define CRED_USER_NS     0x88U

/* struct uid_gid_map */
#define MAP_NR_EXTENTS   0x00U
#define MAP_EXTENT       0x08U
#define MAP_EXTENT_STEP  0x0cU
#define MAP_MAX_EXTENTS  5U

#define MAP_TEXT_SIZE    128

typedef long (*proc_read_fn)(void *file, char *buf, unsigned long count,
                             long long *ppos);
typedef long (*proc_write_fn)(void *file, const char *buf, unsigned long count,
                              long long *ppos);
typedef long long (*proc_llseek_fn)(void *file, long long offset, int whence);

typedef long (*buf_read_fn)(char *to, unsigned long count, long long *ppos,
                            const void *from, unsigned long available);
typedef long (*buf_write_fn)(void *to, unsigned long available, long long *ppos,
                             const char *from, unsigned long count);

typedef void *(*make_inode_fn)(void *sb, void *task, unsigned short mode);
typedef unsigned int (*name_to_int_fn)(const void *qstr);
typedef void *(*find_task_fn)(int nr, void *pid_ns);
typedef void *(*splice_alias_fn)(void *inode, void *dentry);
typedef void (*set_d_op_fn)(void *dentry, const void *ops);
typedef void (*rcu_lock_fn)(void);
typedef void (*put_task_fn)(void *task);

static void *tgid_lookup_addr;
static void *tid_lookup_addr;
static make_inode_fn make_inode_ptr;
static name_to_int_fn name_to_int_ptr;
static find_task_fn find_task_ptr;
static splice_alias_fn splice_alias_ptr;
static set_d_op_fn set_d_op_ptr;
static rcu_lock_fn rcu_lock_ptr;
static rcu_lock_fn rcu_unlock_ptr;
static put_task_fn put_task_ptr;
static buf_read_fn buf_read_ptr;
static buf_write_fn buf_write_ptr;
static proc_llseek_fn llseek_ptr;
static void *pid_dentry_ops_ptr;

static unsigned char uid_map_fops[0x120];
static unsigned char gid_map_fops[0x120];
static unsigned char setgroups_fops[0x120];

static unsigned int installed;

static int fmt_uint(char *dst, unsigned int value, int width)
{
    char digits[10];
    int n = 0;
    int i = 0;
    int pad;

    do {
        digits[n++] = (char)('0' + (value % 10U));
        value /= 10U;
    } while (value);

    for (pad = width - n; pad > 0; pad--)
        dst[i++] = ' ';
    while (n > 0)
        dst[i++] = digits[--n];

    return i;
}

static int map_text(void *ns, unsigned int off, char *out, int size)
{
    unsigned int nr;
    unsigned int i;
    int len = 0;

    nr = dagu_load_u32(ns, off + MAP_NR_EXTENTS);
    if (nr > MAP_MAX_EXTENTS)
        nr = MAP_MAX_EXTENTS;

    for (i = 0; i < nr && len < size - 40; i++) {
        unsigned int base = off + MAP_EXTENT + i * MAP_EXTENT_STEP;
        unsigned int count = dagu_load_u32(ns, base + 8U);

        if (!count)
            continue;

        len += fmt_uint(out + len, dagu_load_u32(ns, base), 10);
        out[len++] = ' ';
        len += fmt_uint(out + len, dagu_load_u32(ns, base + 4U), 10);
        out[len++] = ' ';
        len += fmt_uint(out + len, count, 10);
        out[len++] = '\n';
    }

    return len;
}

static long map_read(void *file, char *ubuf, unsigned long count,
                     long long *ppos, unsigned int off)
{
    void *inode = dagu_load_ptr(file, FILE_F_INODE);
    void *ns = inode ? dagu_load_ptr(inode, INODE_I_PRIVATE) : 0;
    char text[MAP_TEXT_SIZE];
    int len;

    if (!ns || !buf_read_ptr)
        return -5;                              /* -EIO */

    len = map_text(ns, off, text, (int)sizeof(text));

    return buf_read_ptr(ubuf, count, ppos, text, (unsigned long)len);
}

static int is_identity(const char *text)
{
    unsigned int value[3];
    int i;

    for (i = 0; i < 3; i++) {
        unsigned long long acc = 0;
        int digits = 0;

        while (*text == ' ' || *text == '\t')
            text++;
        while (*text >= '0' && *text <= '9') {
            acc = acc * 10ULL + (unsigned int)(*text - '0');
            if (acc > 0xffffffffULL)
                return 0;
            text++;
            digits++;
        }
        if (!digits)
            return 0;
        value[i] = (unsigned int)acc;
    }

    while (*text == ' ' || *text == '\t' || *text == '\n')
        text++;

    return !*text && value[0] == 0U && value[1] == 0U && value[2] == 0xffffffffU;
}

static long map_write(void *file, const char *ubuf, unsigned long count,
                      long long *ppos)
{
    char text[MAP_TEXT_SIZE];
    long ret;

    (void)file;

    if (!buf_write_ptr)
        return -22;                             /* -EINVAL */
    if (*ppos != 0 || !count || count >= (unsigned long)sizeof(text) - 1U)
        return -22;

    ret = buf_write_ptr(text, (unsigned long)sizeof(text) - 1U, ppos, ubuf,
                        count);
    if (ret < 0)
        return ret;

    text[ret] = 0;
    if (!is_identity(text))
        return -1;                              /* -EPERM */

    return ret;
}

static long uid_map_read(void *file, char *ubuf, unsigned long count,
                         long long *ppos)
{
    return map_read(file, ubuf, count, ppos, 0x00U);
}

static long uid_map_write(void *file, const char *ubuf, unsigned long count,
                          long long *ppos)
{
    return map_write(file, ubuf, count, ppos);
}

static long gid_map_read(void *file, char *ubuf, unsigned long count,
                         long long *ppos)
{
    return map_read(file, ubuf, count, ppos, 0x48U);
}

static long gid_map_write(void *file, const char *ubuf, unsigned long count,
                          long long *ppos)
{
    return map_write(file, ubuf, count, ppos);
}

/*
 * Upstream stores the answer in user_namespace.flags, and may_setgroups()
 * reads it back through a stub that answers true whatever is stored, so the
 * write is refused instead of accepted and dropped.
 */
static long setgroups_read(void *file, char *ubuf, unsigned long count,
                           long long *ppos)
{
    static const char deny[] = "deny\n";
    static const char allow[] = "allow\n";
    void *inode = dagu_load_ptr(file, FILE_F_INODE);
    void *ns = inode ? dagu_load_ptr(inode, INODE_I_PRIVATE) : 0;
    const char *text = deny;
    unsigned long len = sizeof(deny) - 1U;

    if (!buf_read_ptr)
        return -5;
    if (ns && (dagu_load_u32(ns, UNS_FLAGS) & SETGROUPS_ALLOWED)) {
        text = allow;
        len = sizeof(allow) - 1U;
    }

    return buf_read_ptr(ubuf, count, ppos, text, len);
}

static long setgroups_write(void *file, const char *ubuf, unsigned long count,
                            long long *ppos)
{
    (void)file;
    (void)ubuf;
    (void)count;
    (void)ppos;

    return -1;
}

static void fill_fops(unsigned char *fops, proc_read_fn read,
                      proc_write_fn write)
{
    dagu_store_ptr(fops, 0x00U, 0);             /* owner */
    dagu_store_ptr(fops, 0x08U, (void *)llseek_ptr);
    dagu_store_ptr(fops, 0x10U, (void *)read);
    dagu_store_ptr(fops, 0x18U, (void *)write);
}

static int name_match(const char *a, const char *b, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

struct proc_name {
    const char *name;
    unsigned int len;
    unsigned char *fops;
};

static const struct proc_name proc_names[] = {
    { "uid_map",  7U, uid_map_fops },
    { "gid_map",  7U, gid_map_fops },
    { "setgroups", 9U, setgroups_fops },
};

static void *instantiate(void *dentry, void *task, void *fops)
{
    void *sb = dagu_load_ptr(dentry, DENTRY_D_SB);
    void *cred;
    void *ns;
    void *inode;

    inode = make_inode_ptr(sb, task, 0100644);
    if (!inode)
        return (void *)-2;                      /* -ENOENT */

    cred = dagu_load_ptr(task, TASK_CRED);
    ns = cred ? dagu_load_ptr(cred, CRED_USER_NS) : 0;

    dagu_store_ptr(inode, INODE_I_FOP, fops);
    dagu_store_ptr(inode, INODE_I_PRIVATE, ns);

    if (set_d_op_ptr && pid_dentry_ops_ptr)
        set_d_op_ptr(dentry, pid_dentry_ops_ptr);

    return splice_alias_ptr(inode, dentry);
}

static void lookup_after(hook_fargs4_t *args, void *udata)
{
    const struct proc_name *match = 0;
    const char *name;
    void *dentry;
    void *parent;
    void *pid_ns;
    void *task;
    void *res;
    unsigned int len;
    unsigned int nr;
    unsigned int i;

    (void)udata;

    if ((long)args->ret != -2)                  /* -ENOENT */
        return;
    if (!make_inode_ptr || !splice_alias_ptr || !name_to_int_ptr ||
        !find_task_ptr || !rcu_lock_ptr || !rcu_unlock_ptr || !put_task_ptr)
        return;

    dentry = (void *)args->arg1;
    if (!dentry)
        return;

    len = dagu_load_u32(dentry, DENTRY_D_NAME + QSTR_LEN);
    name = (const char *)dagu_load_ptr(dentry, DENTRY_D_NAME + QSTR_NAME);
    if (!name)
        return;

    for (i = 0; i < sizeof(proc_names) / sizeof(proc_names[0]); i++) {
        if (proc_names[i].len != len)
            continue;
        if (name_match(proc_names[i].name, name, len)) {
            match = &proc_names[i];
            break;
        }
    }
    if (!match)
        return;

    parent = dagu_load_ptr(dentry, DENTRY_D_PARENT);
    if (!parent)
        return;

    nr = name_to_int_ptr((const char *)parent + DENTRY_D_NAME);
    if (nr == ~0U)
        return;

    pid_ns = dagu_load_ptr(dagu_load_ptr(dentry, DENTRY_D_SB), SB_FS_INFO);
    if (!pid_ns)
        return;

    rcu_lock_ptr();
    task = find_task_ptr((int)nr, pid_ns);
    if (task)
        __atomic_add_fetch((unsigned int *)((char *)task + TASK_USAGE), 1U,
                           __ATOMIC_ACQ_REL);
    rcu_unlock_ptr();

    if (!task)
        return;

    res = instantiate(dentry, task, match->fops);

    if (!__atomic_sub_fetch((unsigned int *)((char *)task + TASK_USAGE), 1U,
                            __ATOMIC_ACQ_REL))
        put_task_ptr(task);

    if (res)
        args->ret = (unsigned long)res;
    else
        args->ret = 0;                          /* alias, successful lookup */
}

int dagu_userns_proc_bind(void)
{
    make_inode_ptr = (make_inode_fn)kallsyms_lookup_name("proc_pid_make_inode");
    name_to_int_ptr = (name_to_int_fn)kallsyms_lookup_name("name_to_int");
    find_task_ptr = (find_task_fn)kallsyms_lookup_name("find_task_by_pid_ns");
    splice_alias_ptr = (splice_alias_fn)kallsyms_lookup_name("d_splice_alias");
    set_d_op_ptr = (set_d_op_fn)kallsyms_lookup_name("d_set_d_op");
    put_task_ptr = (put_task_fn)kallsyms_lookup_name("__put_task_struct");
    rcu_lock_ptr = (rcu_lock_fn)kallsyms_lookup_name("__rcu_read_lock");
    rcu_unlock_ptr = (rcu_lock_fn)kallsyms_lookup_name("__rcu_read_unlock");
    buf_read_ptr = (buf_read_fn)kallsyms_lookup_name("simple_read_from_buffer");
    buf_write_ptr =
        (buf_write_fn)kallsyms_lookup_name("simple_write_to_buffer");
    llseek_ptr = (proc_llseek_fn)kallsyms_lookup_name("generic_file_llseek");
    pid_dentry_ops_ptr = (void *)kallsyms_lookup_name("pid_dentry_operations");
    tgid_lookup_addr = (void *)kallsyms_lookup_name("proc_tgid_base_lookup");
    tid_lookup_addr = (void *)kallsyms_lookup_name("proc_tid_base_lookup");

    if (!make_inode_ptr || !name_to_int_ptr || !find_task_ptr ||
        !splice_alias_ptr || !llseek_ptr)
        return -2;

    fill_fops(uid_map_fops, uid_map_read, uid_map_write);
    fill_fops(gid_map_fops, gid_map_read, gid_map_write);
    fill_fops(setgroups_fops, setgroups_read, setgroups_write);

    return 0;
}

int dagu_userns_proc_install(void)
{
    unsigned int bits = 0;
    hook_err_t rc;

    if (!tgid_lookup_addr || !tid_lookup_addr)
        return 0;

    rc = hook_wrap3(tgid_lookup_addr, 0, lookup_after, 0);
    if (rc == HOOK_NO_ERR)
        bits |= 1U;
    rc = hook_wrap3(tid_lookup_addr, 0, lookup_after, 0);
    if (rc == HOOK_NO_ERR)
        bits |= 2U;

    if (!bits) {
        logkw("ds-dagu-userns: id map lookups not hooked\n");
        return -1;
    }

    __atomic_store_n(&installed, 1U, __ATOMIC_RELEASE);
    logki("ds-dagu-userns: id map files hooked=0x%x\n", bits);

    return 0;
}

void dagu_userns_proc_uninstall(void)
{
    if (!__atomic_load_n(&installed, __ATOMIC_ACQUIRE))
        return;

    __atomic_store_n(&installed, 0U, __ATOMIC_RELEASE);

    if (tgid_lookup_addr)
        hook_unwrap(tgid_lookup_addr, 0, lookup_after);
    if (tid_lookup_addr)
        hook_unwrap(tid_lookup_addr, 0, lookup_after);
}
