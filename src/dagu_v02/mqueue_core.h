/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_MQUEUE_CORE_H
#define DAGU_V02_MQUEUE_CORE_H

struct dagu_ipc_namespace;

int dagu_mq_core_bind(void);
void dagu_mq_destroy_all(struct dagu_ipc_namespace *ns);

long dagu_mq_open(const char *user_name, int oflag, unsigned int mode, void *user_attr);
long dagu_mq_unlink(const char *user_name);
long dagu_mq_timedsend(int mqdes, const char *user_msg, unsigned long length,
                       unsigned int priority, const void *user_timeout);
long dagu_mq_timedreceive(int mqdes, char *user_buffer, unsigned long length,
                          int *user_priority, const void *user_timeout);
long dagu_mq_notify(int mqdes, const void *user_sigevent);
long dagu_mq_getsetattr(int mqdes, const void *user_new, void *user_old);

#endif
