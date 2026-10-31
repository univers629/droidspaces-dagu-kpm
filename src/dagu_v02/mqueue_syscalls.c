/* SPDX-License-Identifier: GPL-2.0-only */
/* POSIX message queue syscall slots on this POSIX_MQUEUE=n ARM64 boot. */

#include "mqueue_core.h"
#include "mqueue_syscalls.h"

#include <hook.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

_Static_assert(__NR_mq_open == 180, "ARM64 mq_open number changed");
_Static_assert(__NR_mq_unlink == 181, "ARM64 mq_unlink number changed");
_Static_assert(__NR_mq_timedsend == 182, "ARM64 mq_timedsend number changed");
_Static_assert(__NR_mq_timedreceive == 183, "ARM64 mq_timedreceive number changed");
_Static_assert(__NR_mq_notify == 184, "ARM64 mq_notify number changed");
_Static_assert(__NR_mq_getsetattr == 185, "ARM64 mq_getsetattr number changed");

static unsigned int installed;
static unsigned int active;

static void before_mq_open(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_open((const char *)syscall_argn(args, 0),
                                            (int)syscall_argn(args, 1),
                                            (unsigned int)syscall_argn(args, 2),
                                            (void *)syscall_argn(args, 3));
    args->skip_origin = 1;
}

static void before_mq_unlink(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_unlink((const char *)syscall_argn(args, 0));
    args->skip_origin = 1;
}

static void before_mq_timedsend(hook_fargs5_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_timedsend((int)syscall_argn(args, 0),
                                                 (const char *)syscall_argn(args, 1),
                                                 (unsigned long)syscall_argn(args, 2),
                                                 (unsigned int)syscall_argn(args, 3),
                                                 (const void *)syscall_argn(args, 4));
    args->skip_origin = 1;
}

static void before_mq_timedreceive(hook_fargs5_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_timedreceive((int)syscall_argn(args, 0),
                                                    (char *)syscall_argn(args, 1),
                                                    (unsigned long)syscall_argn(args, 2),
                                                    (int *)syscall_argn(args, 3),
                                                    (const void *)syscall_argn(args, 4));
    args->skip_origin = 1;
}

static void before_mq_notify(hook_fargs2_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_notify((int)syscall_argn(args, 0),
                                              (const void *)syscall_argn(args, 1));
    args->skip_origin = 1;
}

static void before_mq_getsetattr(hook_fargs3_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_mq_getsetattr((int)syscall_argn(args, 0),
                                                  (const void *)syscall_argn(args, 1),
                                                  (void *)syscall_argn(args, 2));
    args->skip_origin = 1;
}

void dagu_mq_syscalls_uninstall(void)
{
    __atomic_store_n(&active, 0U, __ATOMIC_RELEASE);
    if (installed & 32U)
        fp_unhook_syscalln(__NR_mq_getsetattr, before_mq_getsetattr, 0);
    if (installed & 16U)
        fp_unhook_syscalln(__NR_mq_notify, before_mq_notify, 0);
    if (installed & 8U)
        fp_unhook_syscalln(__NR_mq_timedreceive, before_mq_timedreceive, 0);
    if (installed & 4U)
        fp_unhook_syscalln(__NR_mq_timedsend, before_mq_timedsend, 0);
    if (installed & 2U)
        fp_unhook_syscalln(__NR_mq_unlink, before_mq_unlink, 0);
    if (installed & 1U)
        fp_unhook_syscalln(__NR_mq_open, before_mq_open, 0);
    installed = 0;
}

int dagu_mq_syscalls_install(void)
{
    hook_err_t rc;
    if (installed)
        return -22;
    rc = fp_hook_syscalln(__NR_mq_open, 4, before_mq_open, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 1U;
    rc = fp_hook_syscalln(__NR_mq_unlink, 1, before_mq_unlink, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 2U;
    rc = fp_hook_syscalln(__NR_mq_timedsend, 5, before_mq_timedsend, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 4U;
    rc = fp_hook_syscalln(__NR_mq_timedreceive, 5, before_mq_timedreceive, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 8U;
    rc = fp_hook_syscalln(__NR_mq_notify, 2, before_mq_notify, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 16U;
    rc = fp_hook_syscalln(__NR_mq_getsetattr, 3, before_mq_getsetattr, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 32U;
    __atomic_store_n(&active, 1U, __ATOMIC_RELEASE);
    return 0;
fail:
    dagu_mq_syscalls_uninstall();
    return -(int)rc;
}
