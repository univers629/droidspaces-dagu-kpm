/* SPDX-License-Identifier: GPL-2.0-only */
/* Restore PID namespace status lines omitted by CONFIG_PID_NS=n. */

#include "abi.h"
#include "status_bridge.h"

#include <hook.h>
#include <kallsyms.h>

#define DAGU_PIDNS_MAX_LEVEL 32U
#define DAGU_PIDTYPE_TGID 1U
#define DAGU_PIDTYPE_PID 0U
#define DAGU_PIDTYPE_PGID 2U
#define DAGU_PIDTYPE_SID 3U

typedef void (*seq_puts_fn)(void *, const char *);
typedef int (*seq_write_fn)(void *, const void *, unsigned long);
typedef void (*seq_putc_fn)(void *, char);
typedef void (*seq_put_decimal_fn)(void *, const char *, unsigned long long);
typedef int (*task_pid_nr_ns_fn)(void *, unsigned int, void *);

static seq_puts_fn seq_puts_ptr;
static seq_write_fn seq_write_ptr;
static seq_putc_fn seq_putc_ptr;
static seq_put_decimal_fn seq_put_decimal_ptr;
static task_pid_nr_ns_fn task_pid_nr_ns_ptr;
static void *status_target;
static int installed;

static unsigned long string_length(const char *text)
{
    unsigned long length = 0;
    while (text[length])
        ++length;
    return length;
}

static void put_string(void *seq, const char *text)
{
    if (seq_puts_ptr)
        seq_puts_ptr(seq, text);
    else
        seq_write_ptr(seq, text, string_length(text));
}

static void put_namespace_line(void *seq, const char *tag, void *task,
                               void *proc_ns, void *pid, unsigned int type)
{
    unsigned int namespace_level = dagu_load_u32(proc_ns, DAGU_PIDNS_LEVEL);
    unsigned int pid_level = dagu_load_u32(pid, DAGU_PID_LEVEL);
    unsigned int level;

    if (namespace_level > pid_level || pid_level > DAGU_PIDNS_MAX_LEVEL)
        return;
    put_string(seq, tag);
    for (level = namespace_level; level <= pid_level; ++level) {
        void *upid = (unsigned char *)pid + DAGU_PID_FIRST_UPID + 16U * level;
        void *pid_ns = dagu_load_ptr(upid, DAGU_UPID_NS);
        int number = task_pid_nr_ns_ptr(task, type, pid_ns);
        seq_put_decimal_ptr(seq, "\t", (unsigned long long)(unsigned int)number);
    }
}

static void status_after(hook_fargs4_t *args, void *unused)
{
    void *seq = (void *)args->arg0;
    void *proc_ns = (void *)args->arg1;
    void *pid = (void *)args->arg2;
    void *task = (void *)args->arg3;
    (void)unused;

    if ((long)args->ret || !seq || !proc_ns || !pid || !task)
        return;
    put_namespace_line(seq, "NStgid:", task, proc_ns, pid, DAGU_PIDTYPE_TGID);
    put_namespace_line(seq, "\nNSpid:", task, proc_ns, pid, DAGU_PIDTYPE_PID);
    put_namespace_line(seq, "\nNSpgid:", task, proc_ns, pid, DAGU_PIDTYPE_PGID);
    put_namespace_line(seq, "\nNSsid:", task, proc_ns, pid, DAGU_PIDTYPE_SID);
    seq_putc_ptr(seq, '\n');
}

void dagu_status_bridge_uninstall(void)
{
    if (installed)
        hook_unwrap(status_target, 0, status_after);
    installed = 0;
}

int dagu_status_bridge_install(void)
{
    hook_err_t rc;
    if (installed)
        return -22;

    seq_puts_ptr = (seq_puts_fn)kallsyms_lookup_name("seq_puts");
    if (!seq_puts_ptr)
        seq_puts_ptr = (seq_puts_fn)kallsyms_lookup_name("__seq_puts");
    seq_write_ptr = (seq_write_fn)kallsyms_lookup_name("seq_write");
    seq_putc_ptr = (seq_putc_fn)kallsyms_lookup_name("seq_putc");
    seq_put_decimal_ptr =
        (seq_put_decimal_fn)kallsyms_lookup_name("seq_put_decimal_ull");
    task_pid_nr_ns_ptr =
        (task_pid_nr_ns_fn)kallsyms_lookup_name("__task_pid_nr_ns");
    status_target = (void *)kallsyms_lookup_name("proc_pid_status");
    if ((!seq_puts_ptr && !seq_write_ptr) || !seq_putc_ptr ||
        !seq_put_decimal_ptr || !task_pid_nr_ns_ptr || !status_target)
        return -2;

    rc = hook_wrap4(status_target, 0, status_after, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    installed = 1;
    return 0;
}
