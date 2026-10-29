/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Namespace-scoped SysV semaphores for a boot built without CONFIG_SYSVIPC.
 *
 * The kernel has no semaphore implementation and the four syscalls return
 * ENOSYS. This module keeps semaphore sets in the fake IPC namespace and
 * services semget, semop, semtimedop and semctl from them.
 *
 * semop is the only nontrivial path: an operation list must apply atomically,
 * so the whole list is evaluated under the namespace lock and rolled back if
 * any entry would block without IPC_NOWAIT.
 */

#include "abi.h"
#include "ipc_namespace_internal.h"
#include "sem_core.h"
#include "sem_uapi.h"
#include "usercopy.h"

#include <asm/current.h>
#include <kallsyms.h>

struct dagu_sem_set {
	struct dagu_sem_set *next;
	struct dagu_sem_sem *sems;
	unsigned int nsems;
	int id;
	int key;
	unsigned int mode;
	long otime;
	long ctime;
};

typedef void *(*kmalloc_fn)(unsigned long, unsigned int);
typedef void (*kfree_fn)(const void *);
typedef long (*realtime_seconds_fn)(void);
typedef int (*task_pid_nr_fn)(void *, int, void *);
typedef unsigned long (*sleep_interruptible_fn)(unsigned int);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static realtime_seconds_fn now_ptr;
static task_pid_nr_fn task_pid_nr_ptr;
static sleep_interruptible_fn sleep_ptr;

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

static int current_pid(void)
{
	if (!task_pid_nr_ptr)
		return 0;
	return task_pid_nr_ptr(current, 1, 0);
}

static struct dagu_sem_set *find_key(struct dagu_ipc_namespace *ns, int key)
{
	struct dagu_sem_set *set = (struct dagu_sem_set *)ns->semaphores;

	while (set) {
		if (set->key == key)
			return set;
		set = set->next;
	}
	return 0;
}

static struct dagu_sem_set *find_id(struct dagu_ipc_namespace *ns, int id)
{
	struct dagu_sem_set *set = (struct dagu_sem_set *)ns->semaphores;

	while (set) {
		if (set->id == id)
			return set;
		set = set->next;
	}
	return 0;
}

static unsigned int set_count(struct dagu_ipc_namespace *ns)
{
	struct dagu_sem_set *set = (struct dagu_sem_set *)ns->semaphores;
	unsigned int count = 0;

	while (set) {
		++count;
		set = set->next;
	}
	return count;
}

static void unlink_set(struct dagu_ipc_namespace *ns, struct dagu_sem_set *target)
{
	struct dagu_sem_set **link = (struct dagu_sem_set **)&ns->semaphores;

	while (*link) {
		if (*link == target) {
			*link = target->next;
			break;
		}
		link = &(*link)->next;
	}
}

void dagu_sem_destroy_all(struct dagu_ipc_namespace *ns)
{
	struct dagu_sem_set *set = (struct dagu_sem_set *)ns->semaphores;

	ns->semaphores = 0;
	while (set) {
		struct dagu_sem_set *next = set->next;

		if (set->sems)
			kfree_ptr(set->sems);
		kfree_ptr(set);
		set = next;
	}
}

int dagu_sem_core_bind(void)
{
	kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
	kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
	now_ptr = (realtime_seconds_fn)kallsyms_lookup_name("ktime_get_real_seconds");
	task_pid_nr_ptr = (task_pid_nr_fn)kallsyms_lookup_name("__task_pid_nr_ns");
	sleep_ptr = (sleep_interruptible_fn)kallsyms_lookup_name("schedule_timeout_interruptible");
	if (!kmalloc_ptr || !kfree_ptr || !now_ptr || !task_pid_nr_ptr)
		return -2;
	return 0;
}

long dagu_semget(int key, int nsems, int flags)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_sem_set *existing;
	struct dagu_sem_set *created;
	unsigned int i;
	long result;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}
	if (nsems <= 0 || nsems > DAGU_SEMMSL) {
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	dagu_ipc_namespace_lock(ns);
	existing = find_key(ns, key);
	if (existing && (flags & DAGU_IPC_EXCL)) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -17;
	}
	if (existing) {
		result = existing->id;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return result;
	}
	if (!(flags & DAGU_IPC_CREAT)) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -2;
	}
	if (set_count(ns) >= DAGU_SEMMNI) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -28;
	}

	created = (struct dagu_sem_set *)kmalloc_ptr(sizeof(*created), DAGU_GFP_KERNEL);
	if (!created) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}
	for (i = 0; i < sizeof(*created); ++i)
		((unsigned char *)created)[i] = 0;

	created->sems = (struct dagu_sem_sem *)kmalloc_ptr(
		sizeof(struct dagu_sem_sem) * nsems, DAGU_GFP_KERNEL);
	if (!created->sems) {
		kfree_ptr(created);
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}
	for (i = 0; i < sizeof(struct dagu_sem_sem) * (unsigned long)nsems; ++i) {
		/* volatile keeps the zero fill from folding into a pool load */
		*(volatile unsigned char *)((unsigned char *)created->sems + i) = 0;
	}

	created->nsems = (unsigned int)nsems;
	created->id = (int)ns->next_sem_id++;
	created->key = key;
	created->mode = (unsigned int)(flags & 0777);
	created->ctime = now_ptr();
	created->next = (struct dagu_sem_set *)ns->semaphores;
	ns->semaphores = created;
	result = created->id;

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}

/*
 * Evaluate the whole operation list against a working copy. Returns 0 when
 * every entry can be applied; IPC_NOWAIT blocking yields -EAGAIN without
 * touching the set.
 */
static long apply_ops(struct dagu_sem_sem *work, unsigned int nsems,
		      const struct dagu_sembuf *ops, unsigned long count, int pid,
		      int *touched)
{
	unsigned long i;
	int any = 0;

	for (i = 0; i < count; ++i) {
		unsigned short num = ops[i].sem_num;
		short op = ops[i].sem_op;
		struct dagu_sem_sem *sem;

		if (num >= nsems)
			return -22;
		sem = &work[num];

		if (op > 0) {
			int next = (int)sem->semval + (int)op;

			if (next > DAGU_SEMVMX)
				return -34;
			sem->semval = (unsigned short)next;
			sem->sempid = pid;
			any = 1;
		} else if (op == 0) {
			if (sem->semval != 0)
				return -11;
			sem->sempid = pid;
			any = 1;
		} else {
			int want = -(int)op;

			if ((int)sem->semval < want)
				return -11;
			sem->semval = (unsigned short)((int)sem->semval - want);
			sem->sempid = pid;
			any = 1;
		}
	}
	*touched = any;
	return 0;
}

long dagu_semop(int id, void *user_ops, unsigned long count)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_sem_set *set;
	struct dagu_sembuf local[DAGU_SEMOPM];
	struct dagu_sem_sem *work;
	unsigned long i;
	unsigned long left;
	long result;
	int touched = 0;

	if (count == 0)
		return 0;
	if (count > DAGU_SEMOPM)
		return -22;

	left = dagu_copy_from_user(local, user_ops,
				   sizeof(struct dagu_sembuf) * count);
	if (left)
		return -14;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}

	dagu_ipc_namespace_lock(ns);
	set = find_id(ns, id);
	if (!set) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	work = (struct dagu_sem_sem *)kmalloc_ptr(
		sizeof(struct dagu_sem_sem) * set->nsems, DAGU_GFP_KERNEL);
	if (!work) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}
	for (i = 0; i < sizeof(struct dagu_sem_sem) * set->nsems; ++i)
		((unsigned char *)work)[i] = ((unsigned char *)set->sems)[i];

	result = apply_ops(work, set->nsems, local, count, current_pid(), &touched);
	if (result == 0) {
		for (i = 0; i < sizeof(struct dagu_sem_sem) * set->nsems; ++i) {
			*(volatile unsigned char *)((unsigned char *)set->sems + i) =
				((unsigned char *)work)[i];
		}
		if (touched)
			set->otime = now_ptr();
	}

	kfree_ptr(work);
	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}

long dagu_semtimedop(int id, void *user_ops, unsigned long count, void *user_timeout)
{
	/*
	 * A timeout would need a timer queue. Without one, a blocking request
	 * reports EAGAIN so callers that pass a timeout do not spin forever.
	 */
	(void)user_timeout;
	if (count > DAGU_SEMOPM)
		return -22;
	return dagu_semop(id, user_ops, count);
}

long dagu_semctl(int id, int semnum, int command, void *user_arg)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_sem_set *set;
	long result = 0;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}

	dagu_ipc_namespace_lock(ns);

	if (command == DAGU_IPC_INFO) {
		struct dagu_seminfo info;
		unsigned int i;

		/*
		 * Field-at-a-time volatile stores: adjacent constants would
		 * otherwise fold into a .rodata.cst pool load whose adrp
		 * displacement the loader does not recompute.
		 */
		for (i = 0; i < sizeof(info); ++i)
			*(volatile unsigned char *)((unsigned char *)&info + i) = 0;
		*(volatile int *)&info.semmap = DAGU_SEMMAP;
		*(volatile int *)&info.semmni = DAGU_SEMMNI;
		*(volatile int *)&info.semmns = DAGU_SEMMNS;
		*(volatile int *)&info.semmnu = DAGU_SEMMNS;
		*(volatile int *)&info.semmsl = DAGU_SEMMSL;
		*(volatile int *)&info.semopm = DAGU_SEMOPM;
		*(volatile int *)&info.semume = DAGU_SEMUME;
		*(volatile int *)&info.semusz = 20;
		*(volatile int *)&info.semvmx = DAGU_SEMVMX;
		*(volatile int *)&info.semaem = DAGU_SEMAEM;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &info, sizeof(info)))
			return -14;
		return 0;
	}

	set = find_id(ns, id);
	if (!set) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	switch (command) {
	case DAGU_IPC_RMID:
		unlink_set(ns, set);
		dagu_ipc_namespace_unlock(ns);
		if (set->sems)
			kfree_ptr(set->sems);
		kfree_ptr(set);
		dagu_ipc_namespace_put(ns);
		return 0;

	case DAGU_IPC_STAT: {
		struct dagu_semid64_ds ds;
		unsigned int i;

		for (i = 0; i < sizeof(ds); ++i)
			*(volatile unsigned char *)((unsigned char *)&ds + i) = 0;
		ds.sem_perm.key = set->key;
		ds.sem_perm.uid = 0;
		ds.sem_perm.gid = 0;
		ds.sem_perm.cuid = 0;
		ds.sem_perm.cgid = 0;
		ds.sem_perm.mode = set->mode;
		ds.sem_perm.seq = 0;
		ds.sem_otime = set->otime;
		ds.sem_ctime = set->ctime;
		ds.sem_nsems = set->nsems;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &ds, sizeof(ds)))
			return -14;
		return 0;
	}

	case DAGU_IPC_SET: {
		struct dagu_semid64_ds ds;
		unsigned long left;

		left = dagu_copy_from_user(&ds, user_arg, sizeof(ds));
		if (left) {
			dagu_ipc_namespace_unlock(ns);
			dagu_ipc_namespace_put(ns);
			return -14;
		}
		set->mode = ds.sem_perm.mode & 0777;
		set->ctime = now_ptr();
		result = 0;
		break;
	}

	case DAGU_GETVAL:
		if ((unsigned int)semnum >= set->nsems) {
			result = -22;
			break;
		}
		result = (long)set->sems[semnum].semval;
		break;

	case DAGU_SETVAL:
		if ((unsigned int)semnum >= set->nsems) {
			result = -22;
			break;
		}
		if ((long)user_arg > DAGU_SEMVMX) {
			result = -34;
			break;
		}
		set->sems[semnum].semval = (unsigned short)(long)user_arg;
		set->sems[semnum].sempid = current_pid();
		set->ctime = now_ptr();
		result = 0;
		break;

	case DAGU_GETPID:
		if ((unsigned int)semnum >= set->nsems) {
			result = -22;
			break;
		}
		result = set->sems[semnum].sempid;
		break;

	case DAGU_GETNCNT:
		if ((unsigned int)semnum >= set->nsems) {
			result = -22;
			break;
		}
		result = set->sems[semnum].semncnt;
		break;

	case DAGU_GETZCNT:
		if ((unsigned int)semnum >= set->nsems) {
			result = -22;
			break;
		}
		result = set->sems[semnum].semzcnt;
		break;

	case DAGU_GETALL: {
		unsigned int i;

		for (i = 0; i < set->nsems; ++i) {
			unsigned short value = set->sems[i].semval;

			if (dagu_copy_to_user((unsigned short *)user_arg + i, &value,
					      sizeof(value))) {
				result = -14;
				break;
			}
		}
		break;
	}

	case DAGU_SETALL: {
		unsigned int i;
		unsigned short *values;

		/*
		 * Heap, not stack: a SEM_SETALL request spans up to SEMMSL entries
		 * (32000 * 2 bytes), far beyond the 16 KB kernel stack.
		 */
		values = (unsigned short *)kmalloc_ptr(
			sizeof(unsigned short) * set->nsems, DAGU_GFP_KERNEL);
		if (!values) {
			result = -12;
			break;
		}

		if (dagu_copy_from_user(values, user_arg,
					sizeof(unsigned short) * set->nsems)) {
			kfree_ptr(values);
			result = -14;
			break;
		}
		for (i = 0; i < set->nsems; ++i) {
			if ((long)values[i] > DAGU_SEMVMX) {
				kfree_ptr(values);
				result = -34;
				break;
			}
		}
		if (result)
			break;
		for (i = 0; i < set->nsems; ++i) {
			set->sems[i].semval = values[i];
			set->sems[i].sempid = current_pid();
		}
		set->ctime = now_ptr();
		kfree_ptr(values);
		break;
	}

	default:
		result = -22;
		break;
	}

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}
