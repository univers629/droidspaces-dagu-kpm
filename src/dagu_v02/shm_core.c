/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Namespace-scoped SysV shared memory for a boot built without CONFIG_SYSVIPC.
 *
 * The kernel has neither the segment bookkeeping nor the page cache objects
 * shmget hands out, and the four syscalls return ENOSYS. A segment here is an
 * unlinked tmpfs file obtained from shmem_file_setup(): shmat maps it with
 * vm_mmap(), shmdt unmaps that range again, and the file is dropped once the
 * segment has been removed and its last attach is gone.
 *
 * Attachments are tracked per address space, not per pid: threads share the
 * mapping and only the mm pointer tells them apart from another process.
 * A mapping that dies with its process is not recorded back here, so nattch
 * can read high after an exit without shmdt. That only affects IPC_STAT and
 * delays the release of a removed segment, never the data.
 */

#include "abi.h"
#include "ipc_namespace_internal.h"
#include "shm_core.h"
#include "shm_uapi.h"
#include "usercopy.h"

#include <asm/current.h>
#include <kallsyms.h>

#define DAGU_SHM_ATTACH_MAX	256U

/* vm_mmap() flag and protection bits. */
#define DAGU_MAP_SHARED		0x01UL
#define DAGU_MAP_FIXED		0x10UL
#define DAGU_PROT_READ		0x01UL
#define DAGU_PROT_WRITE		0x02UL
#define DAGU_PROT_EXEC		0x04UL
#define DAGU_VM_NORESERVE	0x00200000UL

struct dagu_shm_seg {
	struct dagu_shm_seg *next;
	void *file;
	unsigned long size;
	int id;
	int key;
	unsigned int mode;
	int cpid;
	int lpid;
	unsigned long nattch;
	long atime;
	long dtime;
	long ctime;
	int removed;
};

struct dagu_shm_attach {
	void *mm;
	unsigned long addr;
	unsigned long size;
	int id;
	int tgid;
	int used;
};

typedef void *(*kmalloc_fn)(unsigned long, unsigned int);
typedef void (*kfree_fn)(const void *);
typedef long (*realtime_seconds_fn)(void);
typedef int (*task_pid_nr_fn)(void *, int, void *);
typedef void *(*shmem_file_setup_fn)(const char *, long long, unsigned long);
typedef unsigned long (*vm_mmap_fn)(void *, unsigned long, unsigned long,
				    unsigned long, unsigned long, unsigned long);
typedef int (*vm_munmap_fn)(unsigned long, unsigned long);
typedef void (*fput_fn)(void *);

static kmalloc_fn kmalloc_ptr;
static kfree_fn kfree_ptr;
static realtime_seconds_fn now_ptr;
static task_pid_nr_fn task_pid_nr_ptr;
static shmem_file_setup_fn file_setup_ptr;
static vm_mmap_fn mmap_ptr;
static vm_munmap_fn munmap_ptr;
static fput_fn fput_ptr;

static void zero_bytes(void *pointer, unsigned long size)
{
	unsigned long i;

	for (i = 0; i < size; ++i)
		*(volatile unsigned char *)((unsigned char *)pointer + i) = 0;
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
	/* SYSVIPC was absent, so restrict the new ABI to privileged callers. */
	return dagu_ipc_namespace_admin(ns);
}

static int current_pid(void)
{
	if (!task_pid_nr_ptr)
		return 0;
	return task_pid_nr_ptr(current, 1, 0);
}

static void *current_mm(void)
{
	return dagu_load_ptr(current, DAGU_TASK_MM);
}

static struct dagu_shm_seg *find_key(struct dagu_ipc_namespace *ns, int key)
{
	struct dagu_shm_seg *seg = (struct dagu_shm_seg *)ns->segments;

	while (seg) {
		if (!seg->removed && seg->key == key)
			return seg;
		seg = seg->next;
	}
	return 0;
}

/* Lookups that must also see a segment already marked for removal. */
static struct dagu_shm_seg *find_any(struct dagu_ipc_namespace *ns, int id)
{
	struct dagu_shm_seg *seg = (struct dagu_shm_seg *)ns->segments;

	while (seg) {
		if (seg->id == id)
			return seg;
		seg = seg->next;
	}
	return 0;
}

static struct dagu_shm_seg *find_id(struct dagu_ipc_namespace *ns, int id)
{
	struct dagu_shm_seg *seg = find_any(ns, id);

	if (seg && seg->removed)
		return 0;
	return seg;
}

static unsigned int seg_count(struct dagu_ipc_namespace *ns)
{
	struct dagu_shm_seg *seg = (struct dagu_shm_seg *)ns->segments;
	unsigned int count = 0;

	while (seg) {
		if (!seg->removed)
			++count;
		seg = seg->next;
	}
	return count;
}

static unsigned long seg_pages(struct dagu_ipc_namespace *ns)
{
	struct dagu_shm_seg *seg = (struct dagu_shm_seg *)ns->segments;
	unsigned long pages = 0;

	while (seg) {
		if (!seg->removed)
			pages += seg->size / DAGU_SHM_PAGE;
		seg = seg->next;
	}
	return pages;
}

static void unlink_seg(struct dagu_ipc_namespace *ns, struct dagu_shm_seg *target)
{
	struct dagu_shm_seg **link = (struct dagu_shm_seg **)&ns->segments;

	while (*link) {
		if (*link == target) {
			*link = target->next;
			break;
		}
		link = &(*link)->next;
	}
}

static void free_seg(struct dagu_shm_seg *seg)
{
	if (seg->file)
		fput_ptr(seg->file);
	kfree_ptr(seg);
}

void dagu_shm_destroy_all(struct dagu_ipc_namespace *ns)
{
	struct dagu_shm_seg *seg = (struct dagu_shm_seg *)ns->segments;

	ns->segments = 0;
	while (seg) {
		struct dagu_shm_seg *next = seg->next;

		free_seg(seg);
		seg = next;
	}
	if (ns->shm_attaches) {
		kfree_ptr(ns->shm_attaches);
		ns->shm_attaches = 0;
	}
}

int dagu_shm_core_bind(void)
{
	kmalloc_ptr = (kmalloc_fn)kallsyms_lookup_name("__kmalloc");
	kfree_ptr = (kfree_fn)kallsyms_lookup_name("kfree");
	now_ptr = (realtime_seconds_fn)kallsyms_lookup_name("ktime_get_real_seconds");
	task_pid_nr_ptr = (task_pid_nr_fn)kallsyms_lookup_name("__task_pid_nr_ns");
	file_setup_ptr = (shmem_file_setup_fn)kallsyms_lookup_name("shmem_file_setup");
	mmap_ptr = (vm_mmap_fn)kallsyms_lookup_name("vm_mmap");
	munmap_ptr = (vm_munmap_fn)kallsyms_lookup_name("vm_munmap");
	fput_ptr = (fput_fn)kallsyms_lookup_name("fput");
	if (!kmalloc_ptr || !kfree_ptr || !now_ptr || !task_pid_nr_ptr ||
	    !file_setup_ptr || !mmap_ptr || !munmap_ptr || !fput_ptr)
		return -2;
	return 0;
}

static struct dagu_shm_attach *attach_table(struct dagu_ipc_namespace *ns)
{
	struct dagu_shm_attach *table;

	if (ns->shm_attaches)
		return (struct dagu_shm_attach *)ns->shm_attaches;
	table = (struct dagu_shm_attach *)kmalloc_ptr(
		(unsigned long)sizeof(struct dagu_shm_attach) * DAGU_SHM_ATTACH_MAX,
		DAGU_GFP_KERNEL);
	if (!table)
		return 0;
	zero_bytes(table, (unsigned long)sizeof(struct dagu_shm_attach) *
			  DAGU_SHM_ATTACH_MAX);
	ns->shm_attaches = table;
	return table;
}

static struct dagu_shm_attach *find_attach(struct dagu_shm_attach *table,
					   void *mm, unsigned long addr)
{
	unsigned int i;

	if (!table)
		return 0;
	for (i = 0; i < DAGU_SHM_ATTACH_MAX; ++i) {
		if (table[i].used && table[i].mm == mm && table[i].addr == addr)
			return &table[i];
	}
	return 0;
}

/* Fallback for a caller whose mm pointer was not the one recorded. */
static struct dagu_shm_attach *find_attach_tgid(struct dagu_shm_attach *table,
						unsigned long addr, int tgid)
{
	unsigned int i;

	if (!table)
		return 0;
	for (i = 0; i < DAGU_SHM_ATTACH_MAX; ++i) {
		if (table[i].used && table[i].addr == addr && table[i].tgid == tgid)
			return &table[i];
	}
	return 0;
}

static struct dagu_shm_attach *free_attach(struct dagu_shm_attach *table)
{
	unsigned int i;

	for (i = 0; i < DAGU_SHM_ATTACH_MAX; ++i) {
		if (!table[i].used)
			return &table[i];
	}
	return 0;
}

long dagu_shmget(int key, unsigned long size, int flags)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_shm_seg *existing;
	struct dagu_shm_seg *created;
	long result;
	int mode;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}
	if (size == 0 || size > DAGU_SHMMAX) {
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	dagu_ipc_namespace_lock(ns);

	if (key != 0) {
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
	}

	if (seg_count(ns) >= DAGU_SHMMNI ||
	    seg_pages(ns) + (size / DAGU_SHM_PAGE) > DAGU_SHMALL) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -28;
	}

	created = (struct dagu_shm_seg *)kmalloc_ptr(sizeof(*created),
						     DAGU_GFP_KERNEL);
	if (!created) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}
	zero_bytes(created, (unsigned long)sizeof(*created));

	created->file = file_setup_ptr("SYSV", (long long)size,
				       DAGU_VM_NORESERVE);
	if (!created->file) {
		kfree_ptr(created);
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}

	mode = flags & 0777;
	if (!mode)
		mode = DAGU_SHM_R | DAGU_SHM_W;

	created->size = (size + DAGU_SHM_PAGE - 1) & ~(DAGU_SHM_PAGE - 1);
	created->id = (int)(ns->next_shm_id++);
	created->key = key;
	created->mode = (unsigned int)mode;
	created->cpid = current_pid();
	created->lpid = created->cpid;
	created->ctime = now_ptr();
	created->next = (struct dagu_shm_seg *)ns->segments;
	ns->segments = created;
	result = created->id;

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}

long dagu_shmat(int id, void *shmaddr, int flags)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_shm_seg *seg;
	struct dagu_shm_attach *table;
	struct dagu_shm_attach *slot;
	unsigned long prot = DAGU_PROT_READ;
	unsigned long map_flags = DAGU_MAP_SHARED;
	unsigned long addr = (unsigned long)shmaddr;
	unsigned long mapped;
	long result;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}

	dagu_ipc_namespace_lock(ns);
	seg = find_id(ns, id);
	if (!seg) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -22;
	}
	table = attach_table(ns);
	if (!table) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}
	slot = free_attach(table);
	if (!slot) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -12;
	}

	if (!(flags & DAGU_SHM_RDONLY))
		prot |= DAGU_PROT_WRITE;
	if (flags & DAGU_SHM_EXEC)
		prot |= DAGU_PROT_EXEC;
	if (addr && (flags & DAGU_SHM_RND))
		addr &= ~(DAGU_SHM_PAGE - 1);
	if (addr)
		map_flags |= DAGU_MAP_FIXED;

	mapped = mmap_ptr(seg->file, addr, seg->size, prot, map_flags, 0);
	if ((long)mapped < 0 && (long)mapped >= -4095) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return (long)mapped;
	}

	slot->mm = current_mm();
	slot->addr = mapped;
	slot->size = seg->size;
	slot->id = seg->id;
	slot->tgid = current_pid();
	slot->used = 1;
	seg->nattch++;
	seg->atime = now_ptr();
	seg->lpid = current_pid();
	result = (long)mapped;

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}

long dagu_shmdt(void *shmaddr)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_shm_attach *table;
	struct dagu_shm_attach *slot;
	struct dagu_shm_seg *seg;
	unsigned long addr = (unsigned long)shmaddr;
	int id;
	int rc;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}

	dagu_ipc_namespace_lock(ns);
	table = (struct dagu_shm_attach *)ns->shm_attaches;
	slot = find_attach(table, current_mm(), addr);
	if (!slot)
		slot = find_attach_tgid(table, addr, current_pid());
	if (!slot) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	id = slot->id;
	slot->used = 0;
	rc = munmap_ptr(addr, slot->size);
	if (rc) {
		slot->used = 1;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return rc;
	}

	seg = find_any(ns, id);
	if (seg) {
		if (seg->nattch)
			seg->nattch--;
		seg->dtime = now_ptr();
		seg->lpid = current_pid();
		if (seg->removed && seg->nattch == 0) {
			unlink_seg(ns, seg);
			free_seg(seg);
		}
	}

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return 0;
}

static void fill_ds(struct dagu_shmid64_ds *ds, const struct dagu_shm_seg *seg)
{
	zero_bytes(ds, (unsigned long)sizeof(*ds));
	*(volatile int *)&ds->shm_perm.key = seg->key;
	*(volatile unsigned int *)&ds->shm_perm.uid = 0;
	*(volatile unsigned int *)&ds->shm_perm.gid = 0;
	*(volatile unsigned int *)&ds->shm_perm.cuid = 0;
	*(volatile unsigned int *)&ds->shm_perm.cgid = 0;
	*(volatile unsigned int *)&ds->shm_perm.mode = seg->mode;
	*(volatile unsigned short *)&ds->shm_perm.seq = 0;
	*(volatile unsigned long *)&ds->shm_segsz = seg->size;
	*(volatile long *)&ds->shm_atime = seg->atime;
	*(volatile long *)&ds->shm_dtime = seg->dtime;
	*(volatile long *)&ds->shm_ctime = seg->ctime;
	*(volatile int *)&ds->shm_cpid = seg->cpid;
	*(volatile int *)&ds->shm_lpid = seg->lpid;
	*(volatile unsigned long *)&ds->shm_nattch = seg->nattch;
}

long dagu_shmctl(int id, int command, void *user_arg)
{
	struct dagu_ipc_namespace *ns;
	struct dagu_shm_seg *seg;
	long result = 0;

	ns = current_ipc();
	if (!ns)
		return -38;
	if (!allowed(ns)) {
		dagu_ipc_namespace_put(ns);
		return -13;
	}

	dagu_ipc_namespace_lock(ns);

	if (command == DAGU_SHM_IPC_INFO) {
		struct dagu_shminfo64 info;

		zero_bytes(&info, (unsigned long)sizeof(info));
		*(volatile unsigned long *)&info.shmmax = DAGU_SHMMAX;
		*(volatile unsigned long *)&info.shmmin = DAGU_SHMMIN;
		*(volatile unsigned long *)&info.shmmni = DAGU_SHMMNI;
		*(volatile unsigned long *)&info.shmseg = DAGU_SHMMNI;
		*(volatile unsigned long *)&info.shmall = DAGU_SHMALL;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &info, sizeof(info)))
			return -14;
		return 0;
	}

	if (command == DAGU_SHM_INFO) {
		struct dagu_shm_info info;

		zero_bytes(&info, (unsigned long)sizeof(info));
		*(volatile int *)&info.used_ids = (int)seg_count(ns);
		*(volatile unsigned long *)&info.shm_tot =
			seg_pages(ns) * DAGU_SHM_PAGE;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &info, sizeof(info)))
			return -14;
		return 0;
	}

	if (command == DAGU_SHM_STAT) {
		struct dagu_shmid64_ds ds;
		unsigned int index = 0;
		struct dagu_shm_seg *walk = (struct dagu_shm_seg *)ns->segments;

		while (walk && index < (unsigned int)id) {
			walk = walk->next;
			++index;
		}
		if (!walk) {
			dagu_ipc_namespace_unlock(ns);
			dagu_ipc_namespace_put(ns);
			return -22;
		}
		fill_ds(&ds, walk);
		result = (long)walk->id;
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &ds, sizeof(ds)))
			return -14;
		return result;
	}

	seg = find_id(ns, id);
	if (!seg) {
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		return -22;
	}

	switch (command) {
	case DAGU_SHM_IPC_RMID:
		seg->removed = 1;
		if (seg->nattch == 0) {
			unlink_seg(ns, seg);
			free_seg(seg);
		}
		result = 0;
		break;

	case DAGU_SHM_IPC_STAT: {
		struct dagu_shmid64_ds ds;

		fill_ds(&ds, seg);
		dagu_ipc_namespace_unlock(ns);
		dagu_ipc_namespace_put(ns);
		if (dagu_copy_to_user(user_arg, &ds, sizeof(ds)))
			return -14;
		return 0;
	}

	case DAGU_SHM_IPC_SET: {
		struct dagu_shmid64_ds ds;

		if (dagu_copy_from_user(&ds, user_arg, sizeof(ds))) {
			result = -14;
			break;
		}
		seg->mode = (unsigned int)(ds.shm_perm.mode & 0777);
		seg->ctime = now_ptr();
		result = 0;
		break;
	}

	case DAGU_SHM_LOCK:
	case DAGU_SHM_UNLOCK:
		/* Nothing is swappable here, so locking is a no-op. */
		result = 0;
		break;

	default:
		result = -22;
		break;
	}

	dagu_ipc_namespace_unlock(ns);
	dagu_ipc_namespace_put(ns);
	return result;
}
