/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_IPC_NAMESPACE_INTERNAL_H
#define DAGU_V02_IPC_NAMESPACE_INTERNAL_H

#include "ipc_namespace.h"

/* Opaque native mutex has ample space; __mutex_init initializes its real fields. */
struct dagu_ipc_namespace {
    unsigned int refs;
    unsigned int reserved;
    struct dagu_ns_common common;
    void *owner_user_ns;
    unsigned char queue_lock[128] __attribute__((aligned(8)));
    void *queues;
    unsigned int next_queue_id;
};

void dagu_ipc_namespace_lock(struct dagu_ipc_namespace *ns);
void dagu_ipc_namespace_unlock(struct dagu_ipc_namespace *ns);
int dagu_ipc_namespace_admin(struct dagu_ipc_namespace *ns);
void dagu_msg_destroy_all(struct dagu_ipc_namespace *ns);

#endif
