/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SysV semaphore syscall slots on this CONFIG_SYSVIPC=n ARM64 boot.
 *
 * The per-syscall table hook is unusable here. Those handlers are eight-byte
 * weak stubs (mov x0, #-38; ret) packed back to back, and the table hook
 * rewrites the entry then resumes at entry+8, which lands on the neighbouring
 * stub. The four semaphore numbers are intercepted at el0_svc_common instead,
 * sharing that chain with the clone3 shim.
 *
 * skip_origin stays clear so do_ni_syscall still runs and the syscall trace
 * hooks keep their existing behaviour; only the return value is replaced.
 */

#include "sem_core.h"
#include "sem_syscalls.h"

#include <asm/ptrace.h>
#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

_Static_assert(__NR_semget == 190, "ARM64 semget number changed");
_Static_assert(__NR_semctl == 191, "ARM64 semctl number changed");
_Static_assert(__NR_semtimedop == 192, "ARM64 semtimedop number changed");
_Static_assert(__NR_semop == 193, "ARM64 semop number changed");

/*
 * Slots 2..4 belong to the clone3 shim; 0, 1, 5, 6 and 7 are free, which is
 * exactly the five slots this shim needs.
 *
 * The syscall arguments must be captured in the before callback: by the time
 * the after callback runs, do_ni_syscall has already overwritten regs[0] with
 * -ENOSYS, so reading the registers there returns the error code instead of
 * the caller's arguments. The regs pointer itself stays available through
 * args->arg0.
 */
#define DAGU_SEM_LOCAL_IS_SEM	0
#define DAGU_SEM_LOCAL_A0	1
#define DAGU_SEM_LOCAL_A1	5
#define DAGU_SEM_LOCAL_A2	6
#define DAGU_SEM_LOCAL_A3	7

#define DAGU_PSR_MODE32_BIT	0x10UL

/* el0_svc_common(struct pt_regs *regs, int scno, int sc_nr, const syscall_fn_t tbl[]) */
#define DAGU_SVC_ARGNO		2

static unsigned long el0_svc_common_addr;
static unsigned int installed;
static unsigned int active;

static int is_semaphore_syscall(unsigned int number)
{
	return number == (unsigned int)__NR_semget ||
	       number == (unsigned int)__NR_semctl ||
	       number == (unsigned int)__NR_semtimedop ||
	       number == (unsigned int)__NR_semop;
}

static long dispatch(unsigned int number, unsigned long arg0,
		     unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	switch (number) {
	case __NR_semget:
		return dagu_semget((int)arg0, (int)arg1, (int)arg2);
	case __NR_semop:
		return dagu_semop((int)arg0, (void *)arg1, (unsigned long)arg2);
	case __NR_semtimedop:
		return dagu_semtimedop((int)arg0, (void *)arg1,
				       (unsigned long)arg2, (void *)arg3);
	case __NR_semctl:
		return dagu_semctl((int)arg0, (int)arg1, (int)arg2, (void *)arg3);
	default:
		return -38;
	}
}

static void before_svc_entry(hook_fargs4_t *args, void *unused)
{
	(void)unused;

	args->local.data[DAGU_SEM_LOCAL_IS_SEM] = 0;

	if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
		return;

	if (!is_semaphore_syscall((uint32_t)args->arg1))
		return;

	{
		struct pt_regs *regs = (struct pt_regs *)args->arg0;

		if (!regs)
			return;
		/* AArch64 only; compat callers reach a different dispatcher. */
		if (regs->pstate & DAGU_PSR_MODE32_BIT)
			return;

		args->local.data[DAGU_SEM_LOCAL_A0] = (unsigned long)regs->regs[0];
		args->local.data[DAGU_SEM_LOCAL_A1] = (unsigned long)regs->regs[1];
		args->local.data[DAGU_SEM_LOCAL_A2] = (unsigned long)regs->regs[2];
		args->local.data[DAGU_SEM_LOCAL_A3] = (unsigned long)regs->regs[3];
		args->local.data[DAGU_SEM_LOCAL_IS_SEM] = 1;
	}
}

static void after_svc_entry(hook_fargs4_t *args, void *unused)
{
	(void)unused;

	if (!args->local.data[DAGU_SEM_LOCAL_IS_SEM])
		return;

	{
		struct pt_regs *regs = (struct pt_regs *)args->arg0;
		unsigned int number = (uint32_t)args->arg1;
		long ret;

		if (!regs)
			return;

		ret = dispatch(number,
			       args->local.data[DAGU_SEM_LOCAL_A0],
			       args->local.data[DAGU_SEM_LOCAL_A1],
			       args->local.data[DAGU_SEM_LOCAL_A2],
			       args->local.data[DAGU_SEM_LOCAL_A3]);
		/*
		 * Overwrite the -ENOSYS that do_ni_syscall left in regs[0].
		 * copy_thread zeroes the child's own regs[0], so this write
		 * affects only the caller's return value.
		 */
		regs->regs[0] = (unsigned long)ret;
		args->ret = (unsigned long)ret;
	}
}

void dagu_sem_syscalls_uninstall(void)
{
	__atomic_store_n(&active, 0U, __ATOMIC_RELEASE);
	if (installed && el0_svc_common_addr)
		hook_unwrap((void *)el0_svc_common_addr,
			    (void *)before_svc_entry, (void *)after_svc_entry);
	installed = 0U;
}

int dagu_sem_syscalls_install(void)
{
	hook_err_t rc;

	if (installed)
		return -22;

	el0_svc_common_addr = kallsyms_lookup_name("el0_svc_common");
	if (!el0_svc_common_addr) {
		logke("ds-dagu-sem: el0_svc_common not found\n");
		return -2;
	}

	/*
	 * Several callback pairs can share one chain; adding to an existing
	 * chain is supported.
	 */
	rc = hook_wrap((void *)el0_svc_common_addr, DAGU_SVC_ARGNO,
		       (void *)before_svc_entry, (void *)after_svc_entry, 0);
	if (rc != HOOK_NO_ERR) {
		logke("ds-dagu-sem: hook el0_svc_common failed rc=%d\n", (int)rc);
		el0_svc_common_addr = 0;
		return -(int)rc;
	}

	installed = 1U;
	__atomic_store_n(&active, 1U, __ATOMIC_RELEASE);
	logki("ds-dagu-sem: semaphore syscalls hooked at el0_svc_common=0x%lx\n",
	      el0_svc_common_addr);
	return 0;
}
