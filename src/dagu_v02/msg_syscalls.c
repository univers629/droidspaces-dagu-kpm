/* SPDX-License-Identifier: GPL-2.0-only */
/* SysV message syscall slots on this CONFIG_SYSVIPC=n ARM64 boot. */

#include "msg_core.h"
#include "msg_syscalls.h"

#include <hook.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

_Static_assert(__NR_msgget == 186, "ARM64 msgget number changed");
_Static_assert(__NR_msgctl == 187, "ARM64 msgctl number changed");
_Static_assert(__NR_msgrcv == 188, "ARM64 msgrcv number changed");
_Static_assert(__NR_msgsnd == 189, "ARM64 msgsnd number changed");

static unsigned int installed;
static unsigned int active;

static void before_msgget(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_msgget((int)syscall_argn(args, 0),
                                            (int)syscall_argn(args, 1));
    args->skip_origin = 1;
}

static void before_msgctl(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_msgctl((int)syscall_argn(args, 0),
                                            (int)syscall_argn(args, 1),
                                            (void *)syscall_argn(args, 2));
    args->skip_origin = 1;
}

static void before_msgrcv(hook_fargs5_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_msgrcv((int)syscall_argn(args, 0),
                                            (void *)syscall_argn(args, 1),
                                            (unsigned long)syscall_argn(args, 2),
                                            (long)syscall_argn(args, 3),
                                            (int)syscall_argn(args, 4));
    args->skip_origin = 1;
}

static void before_msgsnd(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
        return;
    args->ret = (unsigned long)dagu_msgsnd((int)syscall_argn(args, 0),
                                            (const void *)syscall_argn(args, 1),
                                            (unsigned long)syscall_argn(args, 2),
                                            (int)syscall_argn(args, 3));
    args->skip_origin = 1;
}

void dagu_msg_syscalls_uninstall(void)
{
    __atomic_store_n(&active, 0U, __ATOMIC_RELEASE);
    if (installed & 8U)
        fp_unhook_syscalln(__NR_msgsnd, before_msgsnd, 0);
    if (installed & 4U)
        fp_unhook_syscalln(__NR_msgrcv, before_msgrcv, 0);
    if (installed & 2U)
        fp_unhook_syscalln(__NR_msgctl, before_msgctl, 0);
    if (installed & 1U)
        fp_unhook_syscalln(__NR_msgget, before_msgget, 0);
    installed = 0;
}

int dagu_msg_syscalls_install(void)
{
    hook_err_t rc;
    if (installed)
        return -22;
    rc = fp_hook_syscalln(__NR_msgget, 2, before_msgget, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 1U;
    rc = fp_hook_syscalln(__NR_msgctl, 3, before_msgctl, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 2U;
    rc = fp_hook_syscalln(__NR_msgrcv, 5, before_msgrcv, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 4U;
    rc = fp_hook_syscalln(__NR_msgsnd, 4, before_msgsnd, 0, 0);
    if (rc != HOOK_NO_ERR)
        goto fail;
    installed |= 8U;
    __atomic_store_n(&active, 1U, __ATOMIC_RELEASE);
    return 0;
fail:
    dagu_msg_syscalls_uninstall();
    return -(int)rc;
}
