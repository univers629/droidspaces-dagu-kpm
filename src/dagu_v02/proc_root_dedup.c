/* SPDX-License-Identifier: GPL-2.0-only */
/* Reuse the existing root proc node on the one check-only Android caller. */

#include "abi.h"
#include "proc_root_dedup.h"

#include <hook.h>
#include <kallsyms.h>
#include <log.h>

#define DAGU_UEVENTS_RECORDS "uevents_records"
#define DAGU_PROC_SUBDIR_NODE_TO_ENTRY DAGU_PROC_SUBDIR_NODE

typedef unsigned long (*proc_read_lock_irqsave_t)(void *lock);
typedef void (*proc_read_unlock_irqrestore_t)(void *lock,
                                               unsigned long flags);
typedef void (*proc_mutex_init_t)(void *lock, const char *name, void *key);
typedef void (*proc_mutex_lock_t)(void *lock);
typedef void (*proc_mutex_unlock_t)(void *lock);

static void *proc_create_target;
static void *remove_proc_entry_target;
static void *proc_root_entry;
static void *proc_subdir_lock;
static proc_read_lock_irqsave_t proc_read_lock_irqsave;
static proc_read_unlock_irqrestore_t proc_read_unlock_irqrestore;
static proc_mutex_init_t proc_mutex_init;
static proc_mutex_lock_t proc_mutex_lock;
static proc_mutex_unlock_t proc_mutex_unlock;
static void *shared_uevents_entry;
static unsigned char proc_create_serial_lock[256] __attribute__((aligned(64)));
static unsigned char proc_create_lock_key[64] __attribute__((aligned(16)));
static unsigned int hook_flags;
static unsigned int tracked_net_users;
static unsigned int reuse_log_emitted;
static unsigned int retain_log_emitted;
static unsigned int fops_mismatch_log_emitted;

#define DAGU_HOOK_REMOVE_PROC_ENTRY 0x1U
#define DAGU_HOOK_PROC_CREATE       0x2U
#define DAGU_PROC_LOCK_HELD         0x1U
#define DAGU_PROC_CREATE_NATIVE     0x2U

static int is_uevents_records(const char *name)
{
    static const char expected[] = DAGU_UEVENTS_RECORDS;
    unsigned int i;

    if (!name)
        return 0;
    for (i = 0; i < sizeof(expected); ++i)
        if (name[i] != expected[i])
            return 0;
    return 1;
}

static int compare_proc_name(const char *requested, unsigned int requested_len,
                             const char *existing,
                             unsigned int existing_len)
{
    unsigned int i;

    if (requested_len < existing_len)
        return -1;
    if (requested_len > existing_len)
        return 1;
    for (i = 0; i < requested_len; ++i) {
        unsigned char left = (unsigned char)requested[i];
        unsigned char right = (unsigned char)existing[i];
        if (left < right)
            return -1;
        if (left > right)
            return 1;
    }
    return 0;
}

/* The node is embedded at PDE +0x88; proc_register protects this RB tree. */
static void *find_existing_root_entry(void *parent, const char *name)
{
    const unsigned int name_len = sizeof(DAGU_UEVENTS_RECORDS) - 1U;
    void *node;
    void *found = 0;
    unsigned long flags;

    if (!parent)
        parent = proc_root_entry;
    flags = proc_read_lock_irqsave(proc_subdir_lock);
    node = dagu_load_ptr(parent, DAGU_PROC_DIR_SUBDIR_ROOT);
    while (node) {
        const char *existing_name =
            (const char *)dagu_load_ptr(node, DAGU_PROC_NODE_NAME);
        unsigned int existing_len =
            *(const volatile unsigned char *)((const unsigned char *)node +
                                               DAGU_PROC_NODE_NAME_LEN);
        int order = compare_proc_name(name, name_len, existing_name,
                                      existing_len);

        if (!order) {
            found = (unsigned char *)node - DAGU_PROC_SUBDIR_NODE_TO_ENTRY;
            break;
        }
        node = dagu_load_ptr(node, order < 0 ? DAGU_PROC_RB_LEFT :
                                                DAGU_PROC_RB_RIGHT);
    }
    proc_read_unlock_irqrestore(proc_subdir_lock, flags);
    return found;
}

static void proc_create_before(hook_fargs4_t *args, void *unused)
{
    void *existing;

    (void)unused;
    args->local.data0 = 0;
    if (args->arg2 || !is_uevents_records((const char *)args->arg0))
        return;
    /* Serialize lookup with native proc_create so concurrent netns setup cannot race. */
    proc_mutex_lock(proc_create_serial_lock);
    args->local.data0 = DAGU_PROC_LOCK_HELD;
    existing = shared_uevents_entry;
    if (!existing)
        existing = find_existing_root_entry((void *)args->arg2,
                                            (const char *)args->arg0);
    if (!existing) {
        args->local.data0 |= DAGU_PROC_CREATE_NATIVE;
        return;
    }

    shared_uevents_entry = existing;
    if (dagu_load_ptr(existing, DAGU_PROC_ENTRY_FOPS) != (void *)args->arg3 &&
        !__atomic_exchange_n(&fops_mismatch_log_emitted, 1U, __ATOMIC_ACQ_REL))
        logki("ds-dagu-v02: reusing check-only uevents_records despite fops mismatch\n");

    if (!tracked_net_users)
        tracked_net_users = 1U;
    if (tracked_net_users != ~0U)
        ++tracked_net_users;

    /* uevent_net_init only checks this return for NULL; it stores no ref. */
    args->ret = (unsigned long)existing;
    args->skip_origin = 1;
    if (!__atomic_exchange_n(&reuse_log_emitted, 1U, __ATOMIC_ACQ_REL))
        logki("ds-dagu-v02: reusing existing /proc/uevents_records node\n");
}

static void proc_create_after(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (args->local.data0 & DAGU_PROC_CREATE_NATIVE) {
        /* This per-net callback returns success even when proc_create logs NULL. */
        if (args->ret)
            shared_uevents_entry = (void *)args->ret;
        if (tracked_net_users != ~0U)
            ++tracked_net_users;
    }
    if (args->local.data0 & DAGU_PROC_LOCK_HELD)
        proc_mutex_unlock(proc_create_serial_lock);
}

static void remove_proc_entry_before(hook_fargs2_t *args, void *unused)
{
    (void)unused;
    args->local.data1 = 0;
    if (args->arg1 || !is_uevents_records((const char *)args->arg0))
        return;

    proc_mutex_lock(proc_create_serial_lock);
    args->local.data1 = DAGU_PROC_LOCK_HELD;
    if (tracked_net_users > 1U) {
        --tracked_net_users;
        args->ret = 0;
        args->skip_origin = 1;
        if (!__atomic_exchange_n(&retain_log_emitted, 1U, __ATOMIC_ACQ_REL))
            logki("ds-dagu-v02: retaining shared /proc/uevents_records node\n");
    } else if (tracked_net_users == 1U) {
        tracked_net_users = 0U;
        shared_uevents_entry = 0;
    }
}

static void remove_proc_entry_after(hook_fargs2_t *args, void *unused)
{
    (void)unused;
    if (args->local.data1 & DAGU_PROC_LOCK_HELD)
        proc_mutex_unlock(proc_create_serial_lock);
}

int dagu_proc_root_dedup_install(void)
{
    hook_err_t rc;

    if (hook_flags)
        return -22;
    proc_create_target = (void *)kallsyms_lookup_name("proc_create");
    remove_proc_entry_target =
        (void *)kallsyms_lookup_name("remove_proc_entry");
    proc_root_entry = (void *)kallsyms_lookup_name("proc_root");
    proc_subdir_lock = (void *)kallsyms_lookup_name("proc_subdir_lock");
    proc_read_lock_irqsave = (proc_read_lock_irqsave_t)
        kallsyms_lookup_name("_raw_read_lock_irqsave");
    proc_read_unlock_irqrestore = (proc_read_unlock_irqrestore_t)
        kallsyms_lookup_name("_raw_read_unlock_irqrestore");
    proc_mutex_init = (proc_mutex_init_t)
        kallsyms_lookup_name("__mutex_init");
    proc_mutex_lock = (proc_mutex_lock_t)kallsyms_lookup_name("mutex_lock");
    proc_mutex_unlock = (proc_mutex_unlock_t)kallsyms_lookup_name("mutex_unlock");
    if (!proc_create_target || !remove_proc_entry_target || !proc_root_entry ||
        !proc_subdir_lock ||
        !proc_read_lock_irqsave || !proc_read_unlock_irqrestore ||
        !proc_mutex_init || !proc_mutex_lock || !proc_mutex_unlock)
        return -2;

    proc_mutex_init(proc_create_serial_lock, "ds_dagu_proc_root_dedup",
                    proc_create_lock_key);
    proc_mutex_lock(proc_create_serial_lock);
    shared_uevents_entry = find_existing_root_entry(proc_root_entry,
                                                     DAGU_UEVENTS_RECORDS);
    tracked_net_users = shared_uevents_entry ? 1U : 0U;
    proc_mutex_unlock(proc_create_serial_lock);

    rc = hook_wrap2(remove_proc_entry_target, remove_proc_entry_before,
                    remove_proc_entry_after, 0);
    if (rc != HOOK_NO_ERR)
        return -(int)rc;
    hook_flags |= DAGU_HOOK_REMOVE_PROC_ENTRY;
    rc = hook_wrap4(proc_create_target, proc_create_before,
                    proc_create_after, 0);
    if (rc != HOOK_NO_ERR) {
        hook_unwrap(remove_proc_entry_target, remove_proc_entry_before,
                    remove_proc_entry_after);
        hook_flags = 0U;
        return -(int)rc;
    }
    hook_flags |= DAGU_HOOK_PROC_CREATE;
    return 0;
}

void dagu_proc_root_dedup_uninstall(void)
{
    if (hook_flags & DAGU_HOOK_PROC_CREATE) {
        hook_unwrap(proc_create_target, proc_create_before, proc_create_after);
        hook_flags &= ~DAGU_HOOK_PROC_CREATE;
    }
    if (hook_flags & DAGU_HOOK_REMOVE_PROC_ENTRY) {
        hook_unwrap(remove_proc_entry_target, remove_proc_entry_before,
                    remove_proc_entry_after);
        hook_flags &= ~DAGU_HOOK_REMOVE_PROC_ENTRY;
    }
}
