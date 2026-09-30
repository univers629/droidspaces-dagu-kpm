/* SPDX-License-Identifier: GPL-2.0-only */
/* Keep the CONFIG_PID_NS=n do_exit path away from its compiled-in BUG(). */

#include "abi.h"
#include "pid_exit_guard.h"
#include "pid_namespace.h"

#include <asm/current.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>

#define DAGU_PIDNS_MAX_LEVEL 32U
#define DAGU_PIDNS_ADDING 0x80000000U
#define DAGU_PIDNS_REAPER_QUEUE 4096U
#define DAGU_SIGKILL 9
#define DAGU_ECHILD 10L
#define DAGU_EINTR 4L
#define DAGU_ERESTARTSYS 512L
#define DAGU_WALL 0x40000000U

#define DAGU_PIDTYPE_PID 0

typedef void *(*active_pid_ns_fn)(void *task);
typedef void (*disable_pid_allocation_fn)(void *pid_ns);
typedef void *(*idr_get_next_fn)(void *idr, int *nextid);
typedef void *(*pid_task_fn)(void *pid, int type);
typedef int (*send_sig_fn)(int signal, void *task, int priv);
typedef void (*read_lock_fn)(void *lock);
typedef void (*rcu_lock_fn)(void);
typedef unsigned long (*sleep_interruptible_fn)(unsigned int ms);
typedef long (*kernel_wait4_fn)(int pid, void *status, int options, void *rusage);
typedef void *(*kthread_create_fn)(int (*threadfn)(void *), void *data,
                                   int node, const char *namefmt, ...);
typedef int (*wake_up_process_fn)(void *task);
typedef int (*kthread_stop_fn)(void *task);

static active_pid_ns_fn active_pid_ns_ptr;
static disable_pid_allocation_fn disable_pid_allocation_ptr;
static idr_get_next_fn idr_get_next_ptr;
static pid_task_fn pid_task_ptr;
static send_sig_fn send_sig_ptr;
static read_lock_fn read_lock_ptr;
static read_lock_fn read_unlock_ptr;
static rcu_lock_fn rcu_lock_ptr;
static rcu_lock_fn rcu_unlock_ptr;
static sleep_interruptible_fn sleep_ptr;
static kernel_wait4_fn kernel_wait4_ptr;
static kthread_create_fn kthread_create_ptr;
static wake_up_process_fn wake_up_process_ptr;
static kthread_stop_fn kthread_stop_ptr;
static void *tasklist_lock_ptr;
static void *root_pid_ns_ptr;
static void *do_exit_ptr;
static void *reaper_task;
static void *pending_namespaces[DAGU_PIDNS_REAPER_QUEUE];
static unsigned int worker_stopping;
static unsigned int installed;

static int is_fake_pidns(void *ns)
{
    if (!ns || ns == root_pid_ns_ptr ||
        dagu_load_u32(ns, DAGU_PIDNS_LEVEL) == 0U ||
        dagu_load_u32(ns, DAGU_PIDNS_LEVEL) > DAGU_PIDNS_MAX_LEVEL)
        return 0;
    return dagu_load_ptr(ns, DAGU_PIDNS_NS_COMMON + 0x08U) ==
           dagu_pid_proc_operations();
}

static void signal_namespace_tasks(void *ns, void *except)
{
    int nr = 2;
    rcu_lock_ptr();
    read_lock_ptr(tasklist_lock_ptr);
    for (;;) {
        void *pid = idr_get_next_ptr((unsigned char *)ns + DAGU_PIDNS_IDR, &nr);
        void *task;
        if (!pid)
            break;
        task = pid_task_ptr(pid, DAGU_PIDTYPE_PID);
        if (task && task != except)
            send_sig_ptr(DAGU_SIGKILL, task, 1);
        if (nr == 0x7fffffff)
            break;
        ++nr;
    }
    read_unlock_ptr(tasklist_lock_ptr);
    rcu_unlock_ptr();
}

static int queue_reap(void *ns)
{
    unsigned int i;
    for (i = 0; i < DAGU_PIDNS_REAPER_QUEUE; ++i)
        if (__atomic_load_n(&pending_namespaces[i], __ATOMIC_ACQUIRE) == ns)
            return 1;
    dagu_pid_namespace_get(ns);
    for (i = 0; i < DAGU_PIDNS_REAPER_QUEUE; ++i) {
        void *empty = 0;
        if (__atomic_compare_exchange_n(&pending_namespaces[i], &empty, ns, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            wake_up_process_ptr(reaper_task);
            return 1;
        }
    }
    dagu_pid_namespace_put(ns);
    return 0;
}

static void reap_namespace(void *ns)
{
    int rounds;
    long rc;
    disable_pid_allocation_ptr(ns);
    signal_namespace_tasks(ns, reaper_task);
    for (rounds = 0; rounds < 500; ++rounds) {
        rc = kernel_wait4_ptr(-1, 0, (int)DAGU_WALL, 0);
        if (rc == -DAGU_ECHILD) {
            unsigned int allocated = dagu_load_u32(ns, DAGU_PIDNS_ALLOCATED) &
                                     ~DAGU_PIDNS_ADDING;
            if (allocated == 0U)
                break;
            if (allocated > 1U)
                signal_namespace_tasks(ns, reaper_task);
            sleep_ptr(10U);
            continue;
        }
        if (rc == -DAGU_EINTR || rc == -DAGU_ERESTARTSYS)
            continue;
        if (rc < 0) {
            logke("ds-dagu-v02: kernel_wait4 failed while reaping pid namespace (%ld)\n", rc);
            sleep_ptr(10U);
            continue;
        }
    }
    if ((dagu_load_u32(ns, DAGU_PIDNS_ALLOCATED) & ~DAGU_PIDNS_ADDING) != 0U)
        logke("ds-dagu-v02: pid namespace did not drain within 5 seconds\n");
}

static int reaper_worker(void *unused)
{
    unsigned int i;
    (void)unused;
    for (;;) {
        int did_work = 0;
        if (__atomic_load_n(&worker_stopping, __ATOMIC_ACQUIRE))
            return 0;
        for (i = 0; i < DAGU_PIDNS_REAPER_QUEUE; ++i) {
            void *ns = __atomic_exchange_n(&pending_namespaces[i], 0,
                                           __ATOMIC_ACQ_REL);
            if (!ns)
                continue;
            did_work = 1;
            reap_namespace(ns);
            dagu_pid_namespace_put(ns);
        }
        if (!did_work)
            sleep_ptr(20U);
    }
}

static void before_do_exit(hook_fargs1_t *args, void *unused)
{
    void *task = current;
    void *ns;
    void *root_reaper;
    (void)args;
    (void)unused;
    ns = active_pid_ns_ptr(task);
    if (!is_fake_pidns(ns) || dagu_load_ptr(ns, DAGU_PIDNS_CHILD_REAPER) != task)
        return;

    disable_pid_allocation_ptr(ns);
    root_reaper = dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_CHILD_REAPER);
    if (!reaper_task || !root_reaper) {
        /* Keep the task away from the kernel's unconditional BRK. The root
         * reaper can adopt and collect children if the bounded queue is full. */
        signal_namespace_tasks(ns, task);
        dagu_store_ptr(ns, DAGU_PIDNS_CHILD_REAPER, root_reaper);
        logke("ds-dagu-v02: reaper queue exhausted; falling back to root reaper\n");
        return;
    }
    /* Publish the reaper before waking its worker so children cannot be
     * reparented back to the exiting PID 1. */
    dagu_store_ptr(ns, DAGU_PIDNS_CHILD_REAPER, reaper_task);
    if (!queue_reap(ns)) {
        signal_namespace_tasks(ns, task);
        dagu_store_ptr(ns, DAGU_PIDNS_CHILD_REAPER, root_reaper);
        logke("ds-dagu-v02: reaper queue exhausted; falling back to root reaper\n");
        return;
    }
    /* do_exit() now follows the normal non-reaper path; children are
     * reparented to the live KPM worker and collected asynchronously. */
}

static void stop_reaper_worker(void)
{
    if (!reaper_task)
        return;
    __atomic_store_n(&worker_stopping, 1U, __ATOMIC_RELEASE);
    wake_up_process_ptr(reaper_task);
    kthread_stop_ptr(reaper_task);
    reaper_task = 0;
}

void dagu_pid_exit_guard_uninstall(void)
{
    if (installed)
        hook_unwrap(do_exit_ptr, before_do_exit, 0);
    installed = 0;
    stop_reaper_worker();
}

int dagu_pid_exit_guard_install(void)
{
    hook_err_t rc;
    if (installed || reaper_task)
        return -22;
    active_pid_ns_ptr = (active_pid_ns_fn)kallsyms_lookup_name("task_active_pid_ns");
    disable_pid_allocation_ptr = (disable_pid_allocation_fn)kallsyms_lookup_name("disable_pid_allocation");
    idr_get_next_ptr = (idr_get_next_fn)kallsyms_lookup_name("idr_get_next");
    pid_task_ptr = (pid_task_fn)kallsyms_lookup_name("pid_task");
    send_sig_ptr = (send_sig_fn)kallsyms_lookup_name("send_sig");
    read_lock_ptr = (read_lock_fn)kallsyms_lookup_name("_raw_read_lock");
    read_unlock_ptr = (read_lock_fn)kallsyms_lookup_name("_raw_read_unlock");
    rcu_lock_ptr = (rcu_lock_fn)kallsyms_lookup_name("__rcu_read_lock");
    rcu_unlock_ptr = (rcu_lock_fn)kallsyms_lookup_name("__rcu_read_unlock");
    sleep_ptr = (sleep_interruptible_fn)kallsyms_lookup_name("msleep_interruptible");
    kernel_wait4_ptr = (kernel_wait4_fn)kallsyms_lookup_name("kernel_wait4");
    kthread_create_ptr = (kthread_create_fn)kallsyms_lookup_name("kthread_create_on_node");
    wake_up_process_ptr = (wake_up_process_fn)kallsyms_lookup_name("wake_up_process");
    kthread_stop_ptr = (kthread_stop_fn)kallsyms_lookup_name("kthread_stop");
    tasklist_lock_ptr = (void *)kallsyms_lookup_name("tasklist_lock");
    root_pid_ns_ptr = (void *)kallsyms_lookup_name("init_pid_ns");
    do_exit_ptr = (void *)kallsyms_lookup_name("do_exit");
    if (!active_pid_ns_ptr || !disable_pid_allocation_ptr || !idr_get_next_ptr ||
        !pid_task_ptr || !send_sig_ptr || !read_lock_ptr || !read_unlock_ptr ||
        !rcu_lock_ptr || !rcu_unlock_ptr || !sleep_ptr || !kernel_wait4_ptr ||
        !kthread_create_ptr || !wake_up_process_ptr || !kthread_stop_ptr ||
        !tasklist_lock_ptr || !root_pid_ns_ptr || !do_exit_ptr ||
        root_pid_ns_ptr != dagu_pid_root() ||
        !dagu_load_ptr(root_pid_ns_ptr, DAGU_PIDNS_CHILD_REAPER))
        return -2;
    reaper_task = kthread_create_ptr(reaper_worker, 0, -1, "ds-dagu-reaper");
    if ((unsigned long)reaper_task >= (unsigned long)-4095L) {
        reaper_task = 0;
        return -12;
    }
    __atomic_store_n(&worker_stopping, 0U, __ATOMIC_RELEASE);
    wake_up_process_ptr(reaper_task);
    rc = hook_wrap1(do_exit_ptr, before_do_exit, 0, 0);
    if (rc != HOOK_NO_ERR) {
        stop_reaper_worker();
        return -(int)rc;
    }
    installed = 1U;
    return 0;
}
