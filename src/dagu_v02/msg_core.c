/* SPDX-License-Identifier: GPL-2.0-only */
/* Namespace-scoped SysV message queues for the current SYSVIPC=n boot. */

#include "abi.h"
#include "ipc_namespace_internal.h"
#include "msg_core.h"
#include "msg_uapi.h"
#include "usercopy.h"

#include <asm/current.h>
#include <kallsyms.h>

#define DAGU_MSGMAX 8192UL
#define DAGU_MSGMNB 16384UL
#define DAGU_MSGMNB_HARD 1048576UL
#define DAGU_MSGMNI 1024U

struct dagu_msg {
    struct dagu_msg *next;
    long type;
    unsigned long length;
    unsigned char data[];
};

struct dagu_msg_queue {
    struct dagu_msg_queue *next;
    struct dagu_msg *first;
    struct dagu_msg *last;
    int id;
    int key;
    unsigned int mode;
    unsigned int count;
    unsigned long bytes;
    unsigned long limit;
    long stime;
    long rtime;
    long ctime;
    int lspid;
    int lrpid;
};

typedef void *(*kmalloc_fn)(unsigned long, unsigned int);
typedef void (*kfree_fn)(const void *);
typedef unsigned long (*sleep_interruptible_fn)(unsigned int);
typedef long (*realtime_seconds_fn)(void);
typedef int (*task_pid_nr_fn)(void *, int, void *);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static sleep_interruptible_fn sleep_ptr;
static realtime_seconds_fn now_ptr;
static task_pid_nr_fn task_pid_nr_ptr;

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
    /* SYSVIPC was absent, so restrict the new ABI to privileged callers. */
    return dagu_ipc_namespace_admin(ns);
}

static struct dagu_msg_queue *find_key(struct dagu_ipc_namespace *ns, int key)
{
    struct dagu_msg_queue *queue = (struct dagu_msg_queue *)ns->queues;
    while (queue) {
        if (queue->key == key)
            return queue;
        queue = queue->next;
    }
    return 0;
}

static struct dagu_msg_queue *find_id(struct dagu_ipc_namespace *ns, int id)
{
    struct dagu_msg_queue *queue = (struct dagu_msg_queue *)ns->queues;
    while (queue) {
        if (queue->id == id)
            return queue;
        queue = queue->next;
    }
    return 0;
}

static unsigned int queue_count(struct dagu_ipc_namespace *ns)
{
    struct dagu_msg_queue *queue = (struct dagu_msg_queue *)ns->queues;
    unsigned int count = 0;
    while (queue) {
        ++count;
        queue = queue->next;
    }
    return count;
}

static void destroy_queue(struct dagu_msg_queue *queue)
{
    struct dagu_msg *message = queue->first;
    while (message) {
        struct dagu_msg *next = message->next;
        kfree_ptr(message);
        message = next;
    }
    kfree_ptr(queue);
}

void dagu_msg_destroy_all(struct dagu_ipc_namespace *ns)
{
    struct dagu_msg_queue *queue = (struct dagu_msg_queue *)ns->queues;
    ns->queues = 0;
    while (queue) {
        struct dagu_msg_queue *next = queue->next;
        destroy_queue(queue);
        queue = next;
    }
}

int dagu_msg_core_bind(void)
{
    kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
    kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
    sleep_ptr = (sleep_interruptible_fn)kallsyms_lookup_name("msleep_interruptible");
    now_ptr = (realtime_seconds_fn)kallsyms_lookup_name("ktime_get_real_seconds");
    task_pid_nr_ptr = (task_pid_nr_fn)kallsyms_lookup_name("__task_pid_nr_ns");
    if (!kmalloc_ptr || !kfree_ptr ||
        !sleep_ptr || !now_ptr || !task_pid_nr_ptr)
        return -2;
    return 0;
}

long dagu_msgget(int key, int flags)
{
    struct dagu_ipc_namespace *ns = current_ipc();
    struct dagu_msg_queue *candidate = 0;
    struct dagu_msg_queue *queue;
    long result;
    if (!ns)
        return -22;
    if (!allowed(ns)) {
        result = -13;
        goto out;
    }
    for (;;) {
        dagu_ipc_namespace_lock(ns);
        queue = key ? find_key(ns, key) : 0;
        if (queue) {
            result = ((flags & (DAGU_IPC_CREAT | DAGU_IPC_EXCL)) ==
                      (DAGU_IPC_CREAT | DAGU_IPC_EXCL)) ? -17 : queue->id;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        if (key && !(flags & DAGU_IPC_CREAT)) {
            result = -2;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        if (queue_count(ns) >= DAGU_MSGMNI || ns->next_queue_id > 0x7fffffffU) {
            result = -28;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        if (!candidate) {
            dagu_ipc_namespace_unlock(ns);
            candidate = (struct dagu_msg_queue *)kmalloc_ptr(sizeof(*candidate), DAGU_GFP_KERNEL);
            if (!candidate) {
                result = -12;
                break;
            }
            continue;
        }
        /*
         * Field-at-a-time volatile writes keep the compiler from merging
         * adjacent constants into a .rodata.cst pool load (adrp plus a wide
         * load).
         *
         * The KPM loader relocates sections to distinct offsets within
         * mod->start, but the adrp displacement baked in by the linker is
         * computed relative to the link-time .text base and is not recomputed
         * after relocation. Every constant pool load then reads from the
         * wrong address and returns zero, so limit was 0 at runtime instead
         * of DAGU_MSGMNB and msgsnd always returned EAGAIN.
         */
        {
            volatile unsigned long *raw = (volatile unsigned long *)candidate;
            unsigned long zero_i;
            candidate->next = (struct dagu_msg_queue *)ns->queues;
            for (zero_i = 0; zero_i < sizeof(*candidate) / sizeof(unsigned long); zero_i++)
                raw[zero_i] = 0UL;
            candidate->first = 0;
            candidate->last = 0;
            candidate->id = (int)ns->next_queue_id++;
            candidate->key = key;
            candidate->mode = (unsigned int)(flags & 0777);
            candidate->count = 0;
            *(volatile unsigned long *)&candidate->bytes = 0UL;
            *(volatile unsigned long *)&candidate->limit = DAGU_MSGMNB;
            candidate->stime = 0;
            candidate->rtime = 0;
            candidate->ctime = now_ptr();
            candidate->lspid = 0;
            candidate->lrpid = 0;
            __asm__ volatile("dsb sy" ::: "memory");
        }
        ns->queues = candidate;
        result = candidate->id;
        candidate = 0;
        dagu_ipc_namespace_unlock(ns);
        break;
    }
    if (candidate)
        kfree_ptr(candidate);
out:
    dagu_ipc_namespace_put(ns);
    return result;
}

long dagu_msgctl(int id, int command, void *user_buffer)
{
    struct dagu_ipc_namespace *ns = current_ipc();
    struct dagu_msg_queue *queue;
    struct dagu_msg_queue **link;
    struct dagu_msqid64_ds info = {0};
    long result = 0;
    int op = command & ~DAGU_IPC_64;
    if (!ns)
        return -22;
    if (!allowed(ns)) {
        result = -13;
        goto out;
    }
    if (op == DAGU_IPC_SET &&
        dagu_copy_from_user(&info, user_buffer, sizeof(info)) != 0UL) {
        result = -14;
        goto out;
    }
    dagu_ipc_namespace_lock(ns);
    queue = find_id(ns, id);
    if (!queue) {
        result = -22;
        goto unlock;
    }
    if (op == DAGU_IPC_RMID) {
        link = (struct dagu_msg_queue **)&ns->queues;
        while (*link && *link != queue)
            link = &(*link)->next;
        if (*link == queue)
            *link = queue->next;
        dagu_ipc_namespace_unlock(ns);
        destroy_queue(queue);
        goto out;
    }
    if (op == DAGU_IPC_SET) {
        if (info.msg_qbytes < queue->bytes || info.msg_qbytes > DAGU_MSGMNB_HARD) {
            result = -22;
            goto unlock;
        }
        queue->mode = info.msg_perm.mode & 0777U;
        queue->limit = info.msg_qbytes;
        queue->ctime = now_ptr();
        goto unlock;
    }
    if (op != DAGU_IPC_STAT) {
        result = -22;
        goto unlock;
    }
    info.msg_perm.key = queue->key;
    info.msg_perm.mode = (uint16_t)queue->mode;
    info.msg_stime = queue->stime;
    info.msg_rtime = queue->rtime;
    info.msg_ctime = queue->ctime;
    info.msg_cbytes = queue->bytes;
    info.msg_qnum = queue->count;
    info.msg_qbytes = queue->limit;
    info.msg_lspid = queue->lspid;
    info.msg_lrpid = queue->lrpid;
    if (dagu_copy_to_user(user_buffer, &info, sizeof(info)) != 0UL)
        result = -14;
unlock:
    dagu_ipc_namespace_unlock(ns);
out:
    dagu_ipc_namespace_put(ns);
    return result;
}

long dagu_msgsnd(int id, const void *user_buffer, unsigned long size, int flags)
{
    struct dagu_ipc_namespace *ns = current_ipc();
    struct dagu_msg_queue *queue;
    struct dagu_msg *message;
    long result = 0;
    int waited = 0;
    if (!ns)
        return -22;
    if (!allowed(ns)) {
        result = -13;
        goto out;
    }
    if (size > DAGU_MSGMAX) {
        result = -22;
        goto out;
    }
    message = (struct dagu_msg *)kmalloc_ptr(sizeof(*message) + size, DAGU_GFP_KERNEL);
    if (!message) {
        result = -12;
        goto out;
    }
    message->next = 0;
    message->length = size;
    if (dagu_copy_from_user(&message->type, user_buffer, sizeof(long)) != 0UL ||
        dagu_copy_from_user(message->data, (const unsigned char *)user_buffer + sizeof(long), size) != 0UL) {
        result = -14;
        goto free_message;
    }
    if (message->type <= 0) {
        result = -22;
        goto free_message;
    }
    for (;;) {
        dagu_ipc_namespace_lock(ns);
        queue = find_id(ns, id);
        if (!queue) {
            result = waited ? -43 : -22;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        if (queue->bytes + size <= queue->limit && queue->count < DAGU_MSGMNI) {
            if (queue->last)
                queue->last->next = message;
            else
                queue->first = message;
            queue->last = message;
            queue->bytes += size;
            ++queue->count;
            queue->stime = now_ptr();
            queue->lspid = task_pid_nr_ptr(current, 0, 0);
            message = 0;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        dagu_ipc_namespace_unlock(ns);
        if (flags & DAGU_IPC_NOWAIT) {
            result = -11;
            break;
        }
        waited = 1;
        if (sleep_ptr(10U)) {
            result = -4;
            break;
        }
    }
free_message:
    if (message)
        kfree_ptr(message);
out:
    dagu_ipc_namespace_put(ns);
    return result;
}

static struct dagu_msg **select_message(struct dagu_msg_queue *queue, long type, int flags)
{
    struct dagu_msg **link = &queue->first;
    struct dagu_msg **best = 0;
    if (type < 0) {
        unsigned long ceiling = (unsigned long)(-(type + 1L)) + 1UL;
        while (*link) {
            if ((unsigned long)(*link)->type <= ceiling &&
                (!best || (*link)->type < (*best)->type))
                best = link;
            link = &(*link)->next;
        }
        return best;
    }
    while (*link) {
        if (type == 0 || ((flags & DAGU_MSG_EXCEPT) ? (*link)->type != type : (*link)->type == type))
            return link;
        link = &(*link)->next;
    }
    return 0;
}

long dagu_msgrcv(int id, void *user_buffer, unsigned long size, long type, int flags)
{
    struct dagu_ipc_namespace *ns = current_ipc();
    struct dagu_msg_queue *queue;
    struct dagu_msg **link;
    struct dagu_msg *message;
    unsigned long length;
    long result;
    int waited = 0;
    if (!ns)
        return -22;
    if (!allowed(ns)) {
        result = -13;
        goto out;
    }
    if (flags & DAGU_MSG_COPY) {
        result = -22;
        goto out;
    }
    for (;;) {
        dagu_ipc_namespace_lock(ns);
        queue = find_id(ns, id);
        if (!queue) {
            result = waited ? -43 : -22;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        link = select_message(queue, type, flags);
        if (!link) {
            dagu_ipc_namespace_unlock(ns);
            if (flags & DAGU_IPC_NOWAIT) {
                result = -42;
                break;
            }
            waited = 1;
            if (sleep_ptr(10U)) {
                result = -4;
                break;
            }
            continue;
        }
        message = *link;
        if (message->length > size && !(flags & DAGU_MSG_NOERROR)) {
            result = -7;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        length = message->length < size ? message->length : size;
        if (dagu_copy_to_user(user_buffer, &message->type, sizeof(long)) != 0UL ||
            dagu_copy_to_user((unsigned char *)user_buffer + sizeof(long), message->data, length) != 0UL) {
            result = -14;
            dagu_ipc_namespace_unlock(ns);
            break;
        }
        *link = message->next;
        if (queue->last == message) {
            struct dagu_msg *tail = queue->first;
            while (tail && tail->next)
                tail = tail->next;
            queue->last = tail;
        }
        queue->bytes -= message->length;
        --queue->count;
        queue->rtime = now_ptr();
        queue->lrpid = task_pid_nr_ptr(current, 0, 0);
        dagu_ipc_namespace_unlock(ns);
        kfree_ptr(message);
        result = (long)length;
        break;
    }
out:
    dagu_ipc_namespace_put(ns);
    return result;
}
