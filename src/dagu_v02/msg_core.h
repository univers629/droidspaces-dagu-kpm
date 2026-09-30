/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_MSG_CORE_H
#define DAGU_V02_MSG_CORE_H

int dagu_msg_core_bind(void);
long dagu_msgget(int key, int flags);
long dagu_msgctl(int id, int command, void *user_buffer);
long dagu_msgsnd(int id, const void *user_buffer, unsigned long size, int flags);
long dagu_msgrcv(int id, void *user_buffer, unsigned long size, long type, int flags);

#endif
