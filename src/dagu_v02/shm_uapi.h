/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SysV shared memory UAPI for a kernel built without CONFIG_SYSVIPC.
 *
 * shmctl reads and writes the same structures userspace does. On 64-bit arm64
 * shmid_ds resolves to shmid64_ds from asm-generic, whose permission block is
 * ipc64_perm and whose time fields are already 64-bit.
 */
#ifndef DAGU_V02_SHM_UAPI_H
#define DAGU_V02_SHM_UAPI_H

#include "sem_uapi.h"

/* shmctl commands */
#define DAGU_SHM_IPC_RMID	0
#define DAGU_SHM_IPC_SET	1
#define DAGU_SHM_IPC_STAT	2
#define DAGU_SHM_IPC_INFO	3

#define DAGU_SHM_LOCK		11
#define DAGU_SHM_UNLOCK		12
#define DAGU_SHM_STAT		13
#define DAGU_SHM_INFO		14

/* shmat flags */
#define DAGU_SHM_RDONLY		010000
#define DAGU_SHM_RND		020000
#define DAGU_SHM_REMAP		040000
#define DAGU_SHM_EXEC		0100000

/* Permission bits stored in shm_perm.mode. */
#define DAGU_SHM_R		0400
#define DAGU_SHM_W		0200

/* Segment page granularity used for SHM_RND and for size accounting. */
#define DAGU_SHM_PAGE		0x1000UL

#define DAGU_SHMMNI		4096
#define DAGU_SHMMAX		0x10000000UL
#define DAGU_SHMMIN		1UL
#define DAGU_SHMALL		(DAGU_SHMMAX / DAGU_SHM_PAGE)

/* asm-generic/shmbuf.h shmid64_ds as reached through shmctl IPC_STAT. */
struct dagu_shmid64_ds {
	struct dagu_ipc64_perm shm_perm;
	unsigned long shm_segsz;
	long shm_atime;
	long shm_dtime;
	long shm_ctime;
	int shm_cpid;
	int shm_lpid;
	unsigned long shm_nattch;
	unsigned long unused4;
	unsigned long unused5;
};

/* asm-generic/shmbuf.h shminfo64 as reached through shmctl IPC_INFO. */
struct dagu_shminfo64 {
	unsigned long shmmax;
	unsigned long shmmin;
	unsigned long shmmni;
	unsigned long shmseg;
	unsigned long shmall;
	unsigned long unused1;
	unsigned long unused2;
	unsigned long unused3;
	unsigned long unused4;
};

/* uapi/linux/shm.h shm_info as reached through shmctl SHM_INFO. */
struct dagu_shm_info {
	int used_ids;
	unsigned long shm_tot;
	unsigned long shm_rss;
	unsigned long shm_swp;
	unsigned long swap_attempts;
	unsigned long swap_successes;
};

#endif
