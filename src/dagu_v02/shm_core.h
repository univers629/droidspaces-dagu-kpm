/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_SHM_CORE_H
#define DAGU_V02_SHM_CORE_H

int dagu_shm_core_bind(void);
long dagu_shmget(int key, unsigned long size, int flags);
long dagu_shmat(int id, void *shmaddr, int flags);
long dagu_shmdt(void *shmaddr);
long dagu_shmctl(int id, int command, void *user_arg);

#endif
