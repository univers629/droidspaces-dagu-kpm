/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * clone3() for the dagu 4.19 boot, where sys_clone3 is absent.
 *
 * Layout constraints on this kernel:
 *
 *  1) No sys_clone3 symbol; syscall(435) returns -ENOSYS.
 *
 *  2) sys_call_table holds 435 entries, not the upstream 442.
 *     el0_svc_common compares scno against 0x1b2 (434) and branches on
 *     higher values, so 435 reaches do_ni_syscall without a table lookup.
 *     sys_call_table[435] reads back a sibling rodata word rather than a
 *     function pointer, so per-syscall table hooks on 435 write outside the
 *     array and never run.
 *
 *  3) KernelPatch declines its union syscall dispatcher on this image after
 *     reading the second prologue instruction as a Shadow Call Stack marker.
 *     CONFIG_SHADOW_CALL_STACK is unset here, so the inline hook path is
 *     usable.
 *
 *  4) This module hooks el0_svc_common directly instead of the table.
 *     The before callback records the arguments for scno 435 in the transit
 *     frame; the after callback runs _do_fork once the origin has returned
 *     with DAIF restored, then writes the result into regs->regs[0].
 *     skip_origin stays clear so do_ni_syscall and the syscall trace hooks
 *     keep their existing behavior.
 *
 *     _do_fork is not called from before: at el0_svc_common entry DAIF is
 *     still masked, and copy_process there would hold interrupts off.
 *
 *  5) _do_fork uses the six-argument form:
 *       long _do_fork(unsigned long clone_flags, unsigned long stack_start,
 *                     unsigned long stack_size, int __user *parent_tidptr,
 *                     int __user *child_tidptr, unsigned long tls);
 *     The flags word carries exit_signal in its low byte (CSIGNAL); there is
 *     no pidfd, set_tid or cgroup field.
 */

#include "clone3.h"
#include "usercopy.h"

#include <asm/current.h>
#include <asm/ptrace.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>

#define DAGU_NR_CLONE3		435UL
/* Upper bound compared against scno inside el0_svc_common. */
#define DAGU_NR_SYSCALLS	435U
/* pt_regs.pstate sits at 0x108; PSR_MODE32_BIT is the AArch32 marker. */
#define DAGU_PSR_MODE32_BIT	0x10UL

/* el0_svc_common(struct pt_regs *regs, int scno, int sc_nr, const syscall_fn_t tbl[]) */
#define DAGU_SVC_ARGNO		2

/* Six-argument _do_fork, matching arch/arm64/kernel/sys.c SYSCALL_DEFINE5(clone). */
typedef long (*dagu_do_fork_fn)(unsigned long clone_flags,
				unsigned long stack_start,
				unsigned long stack_size,
				int *parent_tidptr,
				int *child_tidptr,
				unsigned long tls);

/*
 * User struct clone_args, ARM64 64-bit layout (include/uapi/linux/sched.h):
 *   __aligned_u64 flags, pidfd, child_tid, parent_tid, exit_signal,
 *                 stack, stack_size, tls, set_tid, set_tid_size, cgroup
 * Eleven fields total 88 bytes; the 4.20 and later cgroup field is absent
 * from earlier sizes, so any size up to that is accepted and only the covered
 * prefix is read.
 */
struct dagu_user_clone_args {
	unsigned long long flags;
	unsigned long long pidfd;
	unsigned long long child_tid;
	unsigned long long parent_tid;
	unsigned long long exit_signal;
	unsigned long long stack;
	unsigned long long stack_size;
	unsigned long long tls;
	unsigned long long set_tid;
	unsigned long long set_tid_size;
	unsigned long long cgroup;		/* ignored on this kernel */
};

/* clone_flags carries exit_signal in its low byte. */
#define DAGU_CSIGNAL		0x000000ffUL

static unsigned long do_fork_addr;
static unsigned long el0_svc_common_addr;
static unsigned int clone3_ready;
static unsigned int installed;
static unsigned int active;

/* Hook activity counters, used for the bounded diagnostic logs below. */
static unsigned int diag_entry_seen;
static unsigned int diag_alive_logged;
static unsigned int diag_clone3_seen;

/* Rejected flags, matching upstream clone3_args_valid(). */
#define DAGU_CLONE_INTO_CGROUP	0x200000000ULL
#define DAGU_CLONE_PIDFD	0x00001000UL

/* Argument validation, matching upstream clone3_args_valid(). */
static int dagu_clone3_args_valid(const struct dagu_user_clone_args *u)
{
	/* CLONE_PIDFD requires a pidfd pointer. */
	if ((u->flags & DAGU_CLONE_PIDFD) && !u->pidfd)
		return 0;
	/* stack_size must be aligned to sizeof(unsigned long). */
	if (u->stack_size & (sizeof(unsigned long) - 1))
		return 0;
	/* stack_size is meaningless without a stack. */
	if (!u->stack && u->stack_size)
		return 0;
	/* set_tid requires a matching size. */
	if (!u->set_tid && u->set_tid_size)
		return 0;
	/* CLONE_INTO_CGROUP is unsupported here. */
	if (u->flags & DAGU_CLONE_INTO_CGROUP)
		return 0;
	return 1;
}

long dagu_clone3(void *uargs, unsigned long size)
{
	struct dagu_user_clone_args u;
	unsigned long flags;

	if (!active || !clone3_ready)
		return -38;		/* ENOSYS until initialised */

	/* The size must cover flags (8 bytes) and stay within the known struct. */
	if (size < 8 || size > sizeof(u))
		return -22;		/* EINVAL */

	{
		unsigned long left;
		unsigned long n = size;
		unsigned char *dst = (unsigned char *)&u;
		unsigned long i;

		for (i = 0; i < sizeof(u); i++)
			dst[i] = 0;
		left = dagu_copy_from_user(&u, uargs, n);
		if (left)
			return -14;	/* EFAULT */
	}

	if (!dagu_clone3_args_valid(&u))
		return -22;		/* EINVAL */

	/*
	 * exit_signal lives in the low byte of clone_flags rather than in its
	 * own field, so fold the user-supplied value into that byte.
	 */
	flags = (unsigned long)u.flags;
	flags &= ~DAGU_CSIGNAL;
	flags |= ((unsigned long)u.exit_signal) & DAGU_CSIGNAL;

	/*
	 * The six-argument form has no pidfd, set_tid or cgroup field.
	 * CLONE_PIDFD is already rejected by the validator above.
	 */
	if (u.flags & DAGU_CLONE_PIDFD)
		return -22;

	return ((dagu_do_fork_fn)do_fork_addr)(flags,
					       (unsigned long)u.stack,
					       (unsigned long)u.stack_size,
					       (int *)(unsigned long)u.parent_tid,
					       (int *)(unsigned long)u.child_tid,
					       (unsigned long)u.tls);
}

/*
 * el0_svc_common inline hook.
 *
 * argno = 2 maps to the four-argument transit, so x0..x3 reach the origin
 * unchanged and fargs->arg0 holds regs while arg1 holds scno.
 *
 * Per-call state travels through fargs->local.data[], which lives in the
 * transit frame and is therefore private to each invocation.
 */
#define DAGU_LOCAL_IS_CLONE3	2	/* call targets syscall 435 */
#define DAGU_LOCAL_UARGS	3	/* user struct clone_args pointer */
#define DAGU_LOCAL_USIZE	4	/* size argument */

static void before_svc_entry(hook_fargs4_t *args, void *unused)
{
	(void)unused;

	args->local.data[DAGU_LOCAL_IS_CLONE3] = 0;

	if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
		return;

	/*
	 * Count only. DAIF is still masked until the prologue executes
	 * `msr DAIF, xzr`, so logging stays in the after callback.
	 */
	__atomic_add_fetch(&diag_entry_seen, 1U, __ATOMIC_ACQ_REL);

	/* arg1 is an int scno; compare the low 32 bits only. */
	if ((uint32_t)args->arg1 != (uint32_t)DAGU_NR_CLONE3)
		return;

	{
		struct pt_regs *regs = (struct pt_regs *)args->arg0;

		if (!regs)
			return;
		/* AArch64 only; compat callers never reach syscall 435. */
		if (regs->pstate & DAGU_PSR_MODE32_BIT)
			return;

		args->local.data[DAGU_LOCAL_UARGS] = regs->regs[0];
		args->local.data[DAGU_LOCAL_USIZE] = regs->regs[1];
		args->local.data[DAGU_LOCAL_IS_CLONE3] = 1;
	}
}

static void after_svc_entry(hook_fargs4_t *args, void *unused)
{
	(void)unused;

	/*
	 * el0_svc_common has returned, so DAIF is restored and the context is
	 * an ordinary sleepable kernel one where printk and _do_fork are safe.
	 *
	 * The first after call confirms the before callback runs at all.
	 */
	if (__atomic_load_n(&diag_alive_logged, __ATOMIC_ACQUIRE) == 0 &&
	    __atomic_load_n(&diag_entry_seen, __ATOMIC_ACQUIRE) > 0) {
		__atomic_store_n(&diag_alive_logged, 1U, __ATOMIC_RELEASE);
		logki("ds-dagu-clone3: entry hook ALIVE (syscalls seen=%u)\n",
		      __atomic_load_n(&diag_entry_seen, __ATOMIC_ACQUIRE));
	}

	if (!args->local.data[DAGU_LOCAL_IS_CLONE3])
		return;

	{
		struct pt_regs *regs = (struct pt_regs *)args->arg0;
		long ret;

		if (!regs)
			return;

		if (__atomic_load_n(&diag_clone3_seen, __ATOMIC_ACQUIRE) < 4U) {
			__atomic_add_fetch(&diag_clone3_seen, 1U, __ATOMIC_ACQ_REL);
			logki("ds-dagu-clone3: intercepted 435 uargs=0x%lx size=0x%lx\n",
			      (unsigned long)args->local.data[DAGU_LOCAL_UARGS],
			      (unsigned long)args->local.data[DAGU_LOCAL_USIZE]);
		}

		ret = dagu_clone3((void *)(unsigned long)args->local.data[DAGU_LOCAL_UARGS],
				  (unsigned long)args->local.data[DAGU_LOCAL_USIZE]);
		/*
		 * Overwrite the -ENOSYS that do_ni_syscall left in regs[0].
		 * copy_thread zeroes the child's own regs[0], so this write
		 * affects only the caller's return value.
		 */
		regs->regs[0] = (unsigned long)ret;
		args->ret = (unsigned long)ret;

		if (__atomic_load_n(&diag_clone3_seen, __ATOMIC_ACQUIRE) <= 4U)
			logki("ds-dagu-clone3: 435 completed ret=%ld\n", ret);
	}
}

void dagu_clone3_uninstall(void)
{
	__atomic_store_n(&active, 0U, __ATOMIC_RELEASE);
	if (installed && el0_svc_common_addr)
		hook_unwrap((void *)el0_svc_common_addr,
			    (void *)before_svc_entry, (void *)after_svc_entry);
	installed = 0U;
}

int dagu_clone3_install(void)
{
	hook_err_t rc;

	if (installed)
		return -22;

	do_fork_addr = kallsyms_lookup_name("_do_fork");
	if (!do_fork_addr) {
		logke("ds-dagu-clone3: _do_fork not found; clone3 will stay ENOSYS\n");
		return -2;	/* ENOENT */
	}
	logki("ds-dagu-clone3: _do_fork resolved at 0x%lx\n", do_fork_addr);

	/* el0_svc_common is a local symbol, resolvable by name. */
	el0_svc_common_addr = kallsyms_lookup_name("el0_svc_common");
	if (!el0_svc_common_addr) {
		logke("ds-dagu-clone3: el0_svc_common not found; clone3 stays ENOSYS\n");
		return -2;
	}
	logki("ds-dagu-clone3: el0_svc_common=0x%lx sc_nr=%u (435 is OUT of table)\n",
	      el0_svc_common_addr, (unsigned int)DAGU_NR_SYSCALLS);

	clone3_ready = 1U;

	/*
	 * Hook the entry function rather than a table slot: 435 never reaches
	 * the table.
	 */
	rc = hook_wrap((void *)el0_svc_common_addr, DAGU_SVC_ARGNO,
		       (void *)before_svc_entry, (void *)after_svc_entry, 0);
	if (rc != HOOK_NO_ERR) {
		logke("ds-dagu-clone3: hook el0_svc_common failed rc=%d\n", (int)rc);
		clone3_ready = 0U;
		el0_svc_common_addr = 0;
		return -(int)rc;
	}
	installed = 1U;
	__atomic_store_n(&active, 1U, __ATOMIC_RELEASE);
	logki("ds-dagu-clone3: clone3 enabled via el0_svc_common inline hook + _do_fork\n");
	return 0;
}
