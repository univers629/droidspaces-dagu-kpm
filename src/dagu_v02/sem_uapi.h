/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SysV semaphore UAPI for a kernel built without CONFIG_SYSVIPC.
 *
 * The layouts follow the arm64 userspace ABI, which semctl reads and writes
 * directly. semid_ds on 64-bit resolves to semid64_ds from asm-generic, and
 * its permission block is ipc64_perm rather than the legacy 32-bit form.
 */
#ifndef DAGU_V02_SEM_UAPI_H
#define DAGU_V02_SEM_UAPI_H

/* semctl commands */
#define DAGU_IPC_RMID		0
#define DAGU_IPC_SET		1
#define DAGU_IPC_STAT		2
#define DAGU_IPC_INFO		3

#define DAGU_GETPID		11
#define DAGU_GETVAL		12
#define DAGU_GETALL		13
#define DAGU_GETNCNT		14
#define DAGU_GETZCNT		15
#define DAGU_SETVAL		16
#define DAGU_SETALL		17

/* semget flags share the ipc.h namespace. */
#define DAGU_IPC_CREAT		00001000
#define DAGU_IPC_EXCL		00002000

#define DAGU_SEMMSL		32000
#define DAGU_SEMMNI		32000
#define DAGU_SEMOPM		500
#define DAGU_SEMVMX		32767
#define DAGU_SEMAEM		DAGU_SEMVMX
#define DAGU_SEMUME		DAGU_SEMOPM
#define DAGU_SEMMNS		(DAGU_SEMMNI * DAGU_SEMMSL)
#define DAGU_SEMMAP		DAGU_SEMMNS

/*
 * asm-generic/ipcbuf.h ipc64_perm, the permission block inside semid64_ds.
 *
 * pad1 is declared as 4 - sizeof(__kernel_mode_t); mode is an unsigned int on
 * arm64, so pad1 is empty and seq lands at offset 24.
 */
struct dagu_ipc64_perm {
	int key;
	unsigned int uid;
	unsigned int gid;
	unsigned int cuid;
	unsigned int cgid;
	unsigned int mode;
	unsigned short seq;
	unsigned short pad2;
	unsigned long unused1;
	unsigned long unused2;
};

/* asm-generic/sembuf.h semid64_ds as reached through semctl IPC_STAT. */
struct dagu_semid64_ds {
	struct dagu_ipc64_perm sem_perm;
	long sem_otime;
	long sem_ctime;
	unsigned long sem_nsems;
	unsigned long unused3;
	unsigned long unused4;
};

/* In-kernel semaphore state; not part of the userspace ABI. */
struct dagu_sem_sem {
	unsigned short semval;
	unsigned short semzcnt;
	unsigned short semncnt;
	int sempid;
};

struct dagu_sembuf {
	unsigned short sem_num;
	short sem_op;
	short sem_flg;
};

struct dagu_seminfo {
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};

#endif
