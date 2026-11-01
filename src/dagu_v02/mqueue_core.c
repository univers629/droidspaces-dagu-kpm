/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * POSIX message queues for a kernel built without CONFIG_POSIX_MQUEUE.
 *
 * The kernel implements mqueue as a filesystem plus six syscalls. Rebuilding
 * that filesystem here would mean inode and dentry work this module cannot
 * own, so the queue state lives in module memory and the descriptor handed to
 * the caller is an anon-inode file whose private data points at the queue.
 * The mqueue filesystem type registered separately keeps runc's mount working;
 * queue entries never appear in that mount.
 *
 * Namespace scope, blocking and limits follow the SysV message queue code in
 * msg_core.c: the queue list hangs off the fake IPC namespace, waits poll with
 * msleep_interruptible, and an interrupted or expired wait is reported the
 * same way.
 */

#include "abi.h"
#include "ipc_namespace.h"
#include "ipc_namespace_internal.h"
#include "mqueue_core.h"
#include "usercopy.h"

#include <asm/current.h>
#include <kallsyms.h>

#define DAGU_MQ_NAME_MAX        64
#define DAGU_MQ_QUEUE_MAX       64
#define DAGU_MQ_MAXMSG_LIMIT    65536L
#define DAGU_MQ_MSGSIZE_LIMIT   1048576L
#define DAGU_MQ_MAXMSG_DEFAULT  10L
#define DAGU_MQ_MSGSIZE_DEFAULT 8192L
#define DAGU_MQ_PRIO_MAX        32768L

#define DAGU_MQ_O_RDWR     0x0002
#define DAGU_MQ_O_CREAT    0x0040
#define DAGU_MQ_O_EXCL     0x0080
#define DAGU_MQ_O_NONBLOCK 0x0800

#define DAGU_MQ_EPERM        (-1L)
#define DAGU_MQ_ENOENT       (-2L)
#define DAGU_MQ_EINTR        (-4L)
#define DAGU_MQ_EBADF        (-9L)
#define DAGU_MQ_EAGAIN       (-11L)
#define DAGU_MQ_ENOMEM       (-12L)
#define DAGU_MQ_EFAULT       (-14L)
#define DAGU_MQ_EEXIST       (-17L)
#define DAGU_MQ_EBUSY        (-16L)
#define DAGU_MQ_EINVAL       (-22L)
#define DAGU_MQ_EMFILE       (-24L)
#define DAGU_MQ_ENAMETOOLONG (-36L)
#define DAGU_MQ_ENOSYS       (-38L)
#define DAGU_MQ_EMSGSIZE     (-90L)
#define DAGU_MQ_ETIMEDOUT    (-110L)

/*
 * struct file offsets for this boot, read from the kernel's own debug
 * information (include/linux/fs.h): f_op at 0x28, private_data at 0xc8.
 * struct file_operations.release sits at 0x78. Only these three are used.
 */
#define DAGU_FILE_OP_OFFSET      0x28U
#define DAGU_FILE_FLAGS_OFFSET   0x40U
#define DAGU_FILE_PRIVATE_OFFSET 0xc8U
#define DAGU_FOPS_RELEASE_OFFSET 0x78U

struct dagu_mq_message {
    struct dagu_mq_message *next;
    unsigned int priority;
    unsigned long length;
    unsigned char data[];
};

struct dagu_mq_queue {
    struct dagu_mq_queue *next;
    struct dagu_ipc_namespace *ns;
    char name[DAGU_MQ_NAME_MAX];
    unsigned int refs;
    unsigned int unlinked;
    unsigned int flags;
    long maxmsg;
    long msgsize;
    unsigned int count;
    struct dagu_mq_message *head;
    /* SIGEV_SIGNAL registration; zero pid means no registration. */
    int notify_pid;
    unsigned int notify_sig;
    unsigned long notify_value;
};

/* The first three members of struct sigevent; the thread part is unused. */
struct dagu_sigevent {
    unsigned long value;
    int signo;
    int notify;
};

#define DAGU_SIGEV_SIGNAL 0
#define DAGU_SIGEV_NONE   1
#define DAGU_SIGEV_THREAD 2
#define DAGU_SI_MESGQ     (-4)
#define DAGU_SIGINFO_SIZE 128U
#define DAGU_SIGINFO_SIGNO  0x00U
#define DAGU_SIGINFO_CODE   0x08U
#define DAGU_SIGINFO_PID    0x10U
#define DAGU_SIGINFO_UID    0x14U
#define DAGU_SIGINFO_VALUE  0x18U

struct dagu_mq_timespec {
    long long tv_sec;
    long long tv_nsec;
};

struct dagu_mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
};

/* release callback slot at the same offset the kernel uses */
struct dagu_mq_fops {
    unsigned char head[DAGU_FOPS_RELEASE_OFFSET];
    int (*release)(void *inode, void *file);
};

typedef void *(*kmalloc_fn)(unsigned long, unsigned int);
typedef void (*kfree_fn)(const void *);
typedef unsigned long (*sleep_interruptible_fn)(unsigned int);
typedef void (*ktime_real_fn)(struct dagu_mq_timespec *);
typedef int (*anon_inode_getfd_fn)(const char *, const void *, void *, int);
typedef void *(*fget_fn)(unsigned int);
typedef void (*fput_fn)(void *);
typedef int (*task_pid_nr_fn)(void *, int, void *);
typedef void *(*find_get_pid_fn)(int);
typedef void *(*get_pid_task_fn)(void *, int);
typedef void (*put_pid_fn)(void *);
typedef void (*put_task_struct_fn)(void *);
typedef int (*send_sig_info_fn)(int, void *, void *);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static sleep_interruptible_fn sleep_ptr;
static ktime_real_fn ktime_real_ptr;
static anon_inode_getfd_fn anon_inode_getfd_ptr;
static fget_fn fget_ptr;
static fput_fn fput_ptr;
static task_pid_nr_fn task_pid_nr_ptr;
static find_get_pid_fn find_get_pid_ptr;
static get_pid_task_fn get_pid_task_ptr;
static put_pid_fn put_pid_ptr;
static put_task_struct_fn put_task_struct_ptr;
static send_sig_info_fn send_sig_info_ptr;

static struct dagu_mq_fops dagu_mq_fops = { { 0 }, 0 };

static int dagu_mq_release(void *inode, void *file);
static void mq_send_notification(int pid, unsigned int signo, unsigned long value);

/* No libc: this object is linked into the KPM and only kernel symbols resolve. */
static unsigned long mq_strlen(const char *text)
{
    unsigned long length = 0;
    while (text[length])
        ++length;
    return length;
}

static int mq_strcmp(const char *left, const char *right)
{
    while (*left && *left == *right) {
        ++left;
        ++right;
    }
    return (int)(unsigned char)*left - (int)(unsigned char)*right;
}

static void mq_copy(char *to, const char *from, unsigned long size)
{
    unsigned long i;
    for (i = 0; i < size; ++i)
        to[i] = from[i];
}

static void mq_zero(void *buffer, unsigned long size)
{
    unsigned char *bytes = (unsigned char *)buffer;
    unsigned long i;
    for (i = 0; i < size; ++i)
        bytes[i] = 0;
}

static struct dagu_ipc_namespace *current_ipc(void)
{
    void *task = current;
    void *proxy = dagu_load_ptr(task, DAGU_TASK_NSPROXY);
    struct dagu_ipc_namespace *ns;
    if (!proxy)
        return 0;
    ns = (struct dagu_ipc_namespace *)dagu_load_ptr(proxy, DAGU_NSPROXY_IPC);
    dagu_ipc_namespace_get(ns);
    return ns;
}

static int allowed(struct dagu_ipc_namespace *ns)
{
    /* POSIX_MQUEUE was absent, so the new ABI is limited to privileged callers. */
    return dagu_ipc_namespace_admin(ns);
}

static void *file_op(void *file)
{
    return *(void **)((char *)file + DAGU_FILE_OP_OFFSET);
}

static void *file_private(void *file)
{
    return *(void **)((char *)file + DAGU_FILE_PRIVATE_OFFSET);
}

static unsigned int file_flags(void *file)
{
    return *(unsigned int *)((char *)file + DAGU_FILE_FLAGS_OFFSET);
}

static void file_set_nonblock(void *file, unsigned int on)
{
    volatile unsigned int *flags = (volatile unsigned int *)((char *)file + DAGU_FILE_FLAGS_OFFSET);
    if (on)
        *flags |= DAGU_MQ_O_NONBLOCK;
    else
        *flags &= ~DAGU_MQ_O_NONBLOCK;
}

static long now_ms(void)
{
    struct dagu_mq_timespec ts = { 0, 0 };
    if (ktime_real_ptr)
        ktime_real_ptr(&ts);
    return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static struct dagu_mq_queue *find_name(struct dagu_ipc_namespace *ns, const char *name)
{
    struct dagu_mq_queue *queue = (struct dagu_mq_queue *)ns->mqueues;
    while (queue) {
        if (!mq_strcmp(queue->name, name))
            return queue;
        queue = queue->next;
    }
    return 0;
}

static void destroy_queue(struct dagu_mq_queue *queue)
{
    struct dagu_mq_message *message = queue->head;
    while (message) {
        struct dagu_mq_message *next = message->next;
        kfree_ptr(message);
        message = next;
    }
    kfree_ptr(queue);
}

void dagu_mq_destroy_all(struct dagu_ipc_namespace *ns)
{
    struct dagu_mq_queue *queue = (struct dagu_mq_queue *)ns->mqueues;
    ns->mqueues = 0;
    while (queue) {
        struct dagu_mq_queue *next = queue->next;
        destroy_queue(queue);
        queue = next;
    }
}

int dagu_mq_core_bind(void)
{
    kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
    kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
    sleep_ptr = (sleep_interruptible_fn)kallsyms_lookup_name("msleep_interruptible");
    ktime_real_ptr = (ktime_real_fn)kallsyms_lookup_name("ktime_get_real_ts64");
    anon_inode_getfd_ptr = (anon_inode_getfd_fn)kallsyms_lookup_name("anon_inode_getfd");
    fget_ptr = (fget_fn)kallsyms_lookup_name("fget");
    fput_ptr = (fput_fn)kallsyms_lookup_name("fput");
    task_pid_nr_ptr = (task_pid_nr_fn)kallsyms_lookup_name("__task_pid_nr_ns");
    find_get_pid_ptr = (find_get_pid_fn)kallsyms_lookup_name("find_get_pid");
    get_pid_task_ptr = (get_pid_task_fn)kallsyms_lookup_name("get_pid_task");
    put_pid_ptr = (put_pid_fn)kallsyms_lookup_name("put_pid");
    put_task_struct_ptr =
        (put_task_struct_fn)kallsyms_lookup_name("__put_task_struct");
    send_sig_info_ptr = (send_sig_info_fn)kallsyms_lookup_name("send_sig_info");
    if (!kmalloc_ptr || !kfree_ptr || !sleep_ptr || !ktime_real_ptr ||
        !anon_inode_getfd_ptr || !fget_ptr || !fput_ptr ||
        !task_pid_nr_ptr || !find_get_pid_ptr || !get_pid_task_ptr ||
        !put_pid_ptr || !put_task_struct_ptr || !send_sig_info_ptr)
        return -2;

    dagu_mq_fops.release = dagu_mq_release;
    return 0;
}

/* The file is released when the caller closes the descriptor. */
static int dagu_mq_release(void *inode, void *file)
{
    struct dagu_mq_queue *queue = (struct dagu_mq_queue *)file_private(file);
    struct dagu_ipc_namespace *ns;
    (void)inode;

    if (!queue)
        return 0;
    ns = queue->ns;
    if (!ns)
        return 0;

    dagu_ipc_namespace_lock(ns);
    if (queue->refs)
        --queue->refs;
    if (queue->unlinked && !queue->refs) {
        struct dagu_mq_queue **link = (struct dagu_mq_queue **)&ns->mqueues;
        while (*link && *link != queue)
            link = &(*link)->next;
        if (*link)
            *link = queue->next;
        destroy_queue(queue);
    }
    dagu_ipc_namespace_unlock(ns);
    return 0;
}

static long copy_name(const char *user_name, char *name)
{
    unsigned long length;
    unsigned long i;

    if (!user_name)
        return DAGU_MQ_ENOENT;
    if (dagu_copy_from_user(name, user_name, DAGU_MQ_NAME_MAX) != 0UL)
        return DAGU_MQ_EFAULT;
    name[DAGU_MQ_NAME_MAX - 1] = 0;

    if (name[0] != '/')
        return DAGU_MQ_EINVAL;
    length = mq_strlen(name);
    if (length < 2)
        return DAGU_MQ_EINVAL;
    for (i = 1; i < length; ++i) {
        if (name[i] == '/')
            return DAGU_MQ_EINVAL;
    }
    return 0;
}

static long queue_count(struct dagu_ipc_namespace *ns)
{
    struct dagu_mq_queue *queue = (struct dagu_mq_queue *)ns->mqueues;
    long count = 0;
    while (queue) {
        ++count;
        queue = queue->next;
    }
    return count;
}

long dagu_mq_open(const char *user_name, int oflag, unsigned int mode, void *user_attr)
{
    struct dagu_ipc_namespace *ns;
    struct dagu_mq_queue *queue;
    struct dagu_mq_attr attr;
    char name[DAGU_MQ_NAME_MAX];
    long result;
    int fd;

    (void)mode;
    ns = current_ipc();
    if (!ns)
        return DAGU_MQ_EINVAL;
    if (!allowed(ns)) {
        dagu_ipc_namespace_put(ns);
        return DAGU_MQ_EPERM;
    }

    result = copy_name(user_name, name);
    if (result) {
        dagu_ipc_namespace_put(ns);
        return result;
    }

    dagu_ipc_namespace_lock(ns);
    queue = find_name(ns, name);
    if (queue) {
        if ((oflag & DAGU_MQ_O_CREAT) && (oflag & DAGU_MQ_O_EXCL)) {
            dagu_ipc_namespace_unlock(ns);
            dagu_ipc_namespace_put(ns);
            return DAGU_MQ_EEXIST;
        }
        ++queue->refs;
    } else {
        if (!(oflag & DAGU_MQ_O_CREAT)) {
            dagu_ipc_namespace_unlock(ns);
            dagu_ipc_namespace_put(ns);
            return DAGU_MQ_ENOENT;
        }
        if (queue_count(ns) >= DAGU_MQ_QUEUE_MAX) {
            dagu_ipc_namespace_unlock(ns);
            dagu_ipc_namespace_put(ns);
            return DAGU_MQ_ENOMEM;
        }
        queue = (struct dagu_mq_queue *)kmalloc_ptr(sizeof(*queue), DAGU_GFP_KERNEL);
        if (!queue) {
            dagu_ipc_namespace_unlock(ns);
            dagu_ipc_namespace_put(ns);
            return DAGU_MQ_ENOMEM;
        }
        mq_zero(queue, sizeof(*queue));
        mq_copy(queue->name, name, DAGU_MQ_NAME_MAX);
        queue->ns = ns;
        queue->maxmsg = DAGU_MQ_MAXMSG_DEFAULT;
        queue->msgsize = DAGU_MQ_MSGSIZE_DEFAULT;
        queue->refs = 1;
        if (user_attr) {
            if (dagu_copy_from_user(&attr, user_attr, sizeof(attr)) != 0UL) {
                kfree_ptr(queue);
                dagu_ipc_namespace_unlock(ns);
                dagu_ipc_namespace_put(ns);
                return DAGU_MQ_EFAULT;
            }
            if (attr.mq_maxmsg > 0 && attr.mq_maxmsg <= DAGU_MQ_MAXMSG_LIMIT)
                queue->maxmsg = attr.mq_maxmsg;
            if (attr.mq_msgsize > 0 && attr.mq_msgsize <= DAGU_MQ_MSGSIZE_LIMIT)
                queue->msgsize = attr.mq_msgsize;
        }
        queue->next = (struct dagu_mq_queue *)ns->mqueues;
        ns->mqueues = queue;
    }
    dagu_ipc_namespace_unlock(ns);

    fd = anon_inode_getfd_ptr("mqueue", &dagu_mq_fops, queue,
                              DAGU_MQ_O_RDWR | (oflag & DAGU_MQ_O_NONBLOCK));
    if (fd < 0) {
        dagu_ipc_namespace_lock(ns);
        if (queue->refs)
            --queue->refs;
        dagu_ipc_namespace_unlock(ns);
        dagu_ipc_namespace_put(ns);
        return DAGU_MQ_EMFILE;
    }
    dagu_ipc_namespace_put(ns);
    return fd;
}

long dagu_mq_unlink(const char *user_name)
{
    struct dagu_ipc_namespace *ns;
    struct dagu_mq_queue *queue;
    struct dagu_mq_queue **link;
    char name[DAGU_MQ_NAME_MAX];
    long result;

    ns = current_ipc();
    if (!ns)
        return DAGU_MQ_EINVAL;
    if (!allowed(ns)) {
        dagu_ipc_namespace_put(ns);
        return DAGU_MQ_EPERM;
    }
    result = copy_name(user_name, name);
    if (result) {
        dagu_ipc_namespace_put(ns);
        return result;
    }

    dagu_ipc_namespace_lock(ns);
    link = (struct dagu_mq_queue **)&ns->mqueues;
    while (*link && mq_strcmp((*link)->name, name))
        link = &(*link)->next;
    queue = *link;
    if (!queue) {
        dagu_ipc_namespace_unlock(ns);
        dagu_ipc_namespace_put(ns);
        return DAGU_MQ_ENOENT;
    }
    *link = queue->next;
    queue->unlinked = 1;
    if (!queue->refs)
        destroy_queue(queue);
    dagu_ipc_namespace_unlock(ns);
    dagu_ipc_namespace_put(ns);
    return 0;
}

static struct dagu_mq_queue *queue_from_fd(int mqdes, void **file_out, long *error)
{
    void *file = fget_ptr((unsigned int)mqdes);
    struct dagu_mq_queue *queue;

    if (!file) {
        *error = DAGU_MQ_EBADF;
        return 0;
    }
    if (file_op(file) != &dagu_mq_fops) {
        fput_ptr(file);
        *error = DAGU_MQ_EBADF;
        return 0;
    }
    queue = (struct dagu_mq_queue *)file_private(file);
    if (!queue) {
        fput_ptr(file);
        *error = DAGU_MQ_EBADF;
        return 0;
    }
    *file_out = file;
    return queue;
}

static long timeout_deadline(const void *user_timeout)
{
    struct dagu_mq_timespec ts;

    if (!user_timeout)
        return -1;
    if (dagu_copy_from_user(&ts, user_timeout, sizeof(ts)) != 0UL)
        return DAGU_MQ_EFAULT;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL)
        return DAGU_MQ_EINVAL;
    return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void insert_message(struct dagu_mq_queue *queue, struct dagu_mq_message *message)
{
    struct dagu_mq_message **link = &queue->head;

    while (*link && (*link)->priority >= message->priority)
        link = &(*link)->next;
    message->next = *link;
    *link = message;
    ++queue->count;
}

long dagu_mq_timedsend(int mqdes, const char *user_msg, unsigned long length,
                       unsigned int priority, const void *user_timeout)
{
    struct dagu_mq_queue *queue;
    struct dagu_ipc_namespace *ns;
    struct dagu_mq_message *message;
    void *file = 0;
    long deadline;
    long result = 0;
    int notify_pid = 0;
    unsigned int notify_sig = 0;
    unsigned long notify_value = 0;

    queue = queue_from_fd(mqdes, &file, &result);
    if (!queue)
        return result;
    ns = queue->ns;

    if (length > (unsigned long)queue->msgsize || priority > DAGU_MQ_PRIO_MAX) {
        fput_ptr(file);
        return DAGU_MQ_EINVAL;
    }
    deadline = timeout_deadline(user_timeout);
    if (deadline == DAGU_MQ_EFAULT || deadline == DAGU_MQ_EINVAL) {
        fput_ptr(file);
        return deadline;
    }

    message = (struct dagu_mq_message *)kmalloc_ptr(sizeof(*message) + length, DAGU_GFP_KERNEL);
    if (!message) {
        fput_ptr(file);
        return DAGU_MQ_ENOMEM;
    }
    message->next = 0;
    message->priority = priority;
    message->length = length;
    if (length && dagu_copy_from_user(message->data, user_msg, length) != 0UL) {
        kfree_ptr(message);
        fput_ptr(file);
        return DAGU_MQ_EFAULT;
    }

    for (;;) {
        dagu_ipc_namespace_lock(ns);
        if (queue->count < (unsigned int)queue->maxmsg) {
            /* A message arriving on an empty queue fires the registration. */
            if (queue->count == 0 && queue->notify_pid) {
                notify_pid = queue->notify_pid;
                notify_sig = queue->notify_sig;
                notify_value = queue->notify_value;
                queue->notify_pid = 0;
            }
            insert_message(queue, message);
            dagu_ipc_namespace_unlock(ns);
            if (notify_pid)
                mq_send_notification(notify_pid, notify_sig, notify_value);
            break;
        }
        dagu_ipc_namespace_unlock(ns);
        if (file_flags(file) & DAGU_MQ_O_NONBLOCK) {
            result = DAGU_MQ_EAGAIN;
            break;
        }
        if (deadline >= 0 && now_ms() >= deadline) {
            result = DAGU_MQ_ETIMEDOUT;
            break;
        }
        if (sleep_ptr(10U)) {
            result = DAGU_MQ_EINTR;
            break;
        }
    }
    if (result)
        kfree_ptr(message);
    fput_ptr(file);
    return result;
}

long dagu_mq_timedreceive(int mqdes, char *user_buffer, unsigned long length,
                          int *user_priority, const void *user_timeout)
{
    struct dagu_mq_queue *queue;
    struct dagu_ipc_namespace *ns;
    struct dagu_mq_message *message;
    void *file = 0;
    unsigned long msgsize;
    unsigned int priority;
    unsigned long received;
    long deadline;
    long result = 0;

    queue = queue_from_fd(mqdes, &file, &result);
    if (!queue)
        return result;
    ns = queue->ns;
    msgsize = (unsigned long)queue->msgsize;

    if (length < msgsize) {
        fput_ptr(file);
        return DAGU_MQ_EMSGSIZE;
    }
    deadline = timeout_deadline(user_timeout);
    if (deadline == DAGU_MQ_EFAULT || deadline == DAGU_MQ_EINVAL) {
        fput_ptr(file);
        return deadline;
    }

    for (;;) {
        dagu_ipc_namespace_lock(ns);
        message = queue->head;
        if (message) {
            queue->head = message->next;
            --queue->count;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        dagu_ipc_namespace_unlock(ns);
        if (file_flags(file) & DAGU_MQ_O_NONBLOCK) {
            result = DAGU_MQ_EAGAIN;
            break;
        }
        if (deadline >= 0 && now_ms() >= deadline) {
            result = DAGU_MQ_ETIMEDOUT;
            break;
        }
        if (sleep_ptr(10U)) {
            result = DAGU_MQ_EINTR;
            break;
        }
    }
    if (result) {
        fput_ptr(file);
        return result;
    }

    received = message->length;
    priority = message->priority;
    if (received && dagu_copy_to_user(user_buffer, message->data, received) != 0UL) {
        kfree_ptr(message);
        fput_ptr(file);
        return DAGU_MQ_EFAULT;
    }
    if (user_priority &&
        dagu_copy_to_user(user_priority, &priority, sizeof(priority)) != 0UL) {
        kfree_ptr(message);
        fput_ptr(file);
        return DAGU_MQ_EFAULT;
    }
    kfree_ptr(message);
    fput_ptr(file);
    return (long)received;
}


static int mq_current_pid(void)
{
    return task_pid_nr_ptr(current, 1, 0);
}

/*
 * Send the registration's signal. The siginfo is laid out the way the kernel
 * reads it for SI_MESGQ: signo, code, and the realtime fields at their
 * offsets in struct siginfo.
 */
static void mq_send_notification(int pid, unsigned int signo, unsigned long value)
{
    unsigned char info[DAGU_SIGINFO_SIZE] __attribute__((aligned(8)));
    void *upid;
    void *task;
    unsigned int i;

    if (!signo || pid <= 0)
        return;
    for (i = 0; i < DAGU_SIGINFO_SIZE; ++i)
        info[i] = 0;
    dagu_store_u32(info, DAGU_SIGINFO_SIGNO, signo);
    dagu_store_u32(info, DAGU_SIGINFO_CODE, (unsigned int)DAGU_SI_MESGQ);
    dagu_store_u32(info, DAGU_SIGINFO_PID, (unsigned int)mq_current_pid());
    dagu_store_u32(info, DAGU_SIGINFO_UID, 0U);
    dagu_store_ptr(info, DAGU_SIGINFO_VALUE, (void *)value);

    upid = find_get_pid_ptr(pid);
    if (!upid)
        return;
    task = get_pid_task_ptr(upid, 0);
    put_pid_ptr(upid);
    if (!task)
        return;
    send_sig_info_ptr((int)signo, info, task);
    /*
     * put_task_struct() is an inline on this kernel; drop the usage count the
     * same way and hand the last reference to the out-of-line destructor.
     */
    if (__atomic_sub_fetch(
            (unsigned int *)((char *)task + DAGU_TASK_USAGE), 1U,
            __ATOMIC_ACQ_REL) == 0U)
        put_task_struct_ptr(task);
}

long dagu_mq_notify(int mqdes, const void *user_sigevent)
{
    struct dagu_mq_queue *queue;
    struct dagu_ipc_namespace *ns;
    struct dagu_sigevent event;
    void *file = 0;
    long result = 0;

    queue = queue_from_fd(mqdes, &file, &result);
    if (!queue)
        return result;
    ns = queue->ns;

    if (user_sigevent) {
        if (dagu_copy_from_user(&event, user_sigevent, sizeof(event)) != 0UL) {
            fput_ptr(file);
            return DAGU_MQ_EFAULT;
        }
        if (event.notify == DAGU_SIGEV_THREAD ||
            event.notify < DAGU_SIGEV_SIGNAL ||
            event.notify > DAGU_SIGEV_NONE) {
            fput_ptr(file);
            return DAGU_MQ_EINVAL;
        }
        if (event.notify == DAGU_SIGEV_SIGNAL &&
            (event.signo <= 0 || event.signo > 64)) {
            fput_ptr(file);
            return DAGU_MQ_EINVAL;
        }
    }

    dagu_ipc_namespace_lock(ns);
    if (!user_sigevent) {
        if (!queue->notify_pid)
            result = DAGU_MQ_EINVAL;
        else
            queue->notify_pid = 0;
    } else if (queue->notify_pid) {
        result = DAGU_MQ_EBUSY;
    } else {
        queue->notify_pid = mq_current_pid();
        queue->notify_sig = (event.notify == DAGU_SIGEV_SIGNAL) ?
                            (unsigned int)event.signo : 0U;
        queue->notify_value = event.value;
    }
    dagu_ipc_namespace_unlock(ns);
    fput_ptr(file);
    return result;
}

long dagu_mq_getsetattr(int mqdes, const void *user_new, void *user_old)
{
    struct dagu_mq_queue *queue;
    struct dagu_mq_attr attr;
    void *file = 0;
    long result = 0;

    queue = queue_from_fd(mqdes, &file, &result);
    if (!queue)
        return result;

    dagu_ipc_namespace_lock(queue->ns);
    attr.mq_flags = (long)(file_flags(file) & DAGU_MQ_O_NONBLOCK);
    attr.mq_maxmsg = queue->maxmsg;
    attr.mq_msgsize = queue->msgsize;
    attr.mq_curmsgs = (long)queue->count;
    if (user_new) {
        struct dagu_mq_attr requested;
        if (dagu_copy_from_user(&requested, user_new, sizeof(requested)) != 0UL) {
            dagu_ipc_namespace_unlock(queue->ns);
            fput_ptr(file);
            return DAGU_MQ_EFAULT;
        }
        file_set_nonblock(file, (unsigned int)(requested.mq_flags & DAGU_MQ_O_NONBLOCK));
    }
    dagu_ipc_namespace_unlock(queue->ns);

    if (user_old && dagu_copy_to_user(user_old, &attr, sizeof(attr)) != 0UL) {
        fput_ptr(file);
        return DAGU_MQ_EFAULT;
    }
    fput_ptr(file);
    return 0;
}
