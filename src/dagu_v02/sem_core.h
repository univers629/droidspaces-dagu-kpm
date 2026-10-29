/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_SEM_CORE_H
#define DAGU_V02_SEM_CORE_H

int dagu_sem_core_bind(void);
long dagu_semget(int key, int nsems, int flags);
long dagu_semop(int id, void *user_ops, unsigned long count);
long dagu_semtimedop(int id, void *user_ops, unsigned long count, void *user_timeout);
long dagu_semctl(int id, int semnum, int command, void *user_arg);

#endif
