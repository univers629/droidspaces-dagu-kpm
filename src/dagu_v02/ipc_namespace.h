/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_IPC_NAMESPACE_H
#define DAGU_V02_IPC_NAMESPACE_H

#include "ns_types.h"

struct dagu_ipc_namespace;

int dagu_ipc_namespace_bind(void);
struct dagu_ipc_namespace *dagu_ipc_root(void);
struct dagu_ipc_namespace *dagu_ipc_namespace_create(void *owner_user_ns);
void dagu_ipc_namespace_get(struct dagu_ipc_namespace *ns);
void dagu_ipc_namespace_put(struct dagu_ipc_namespace *ns);
const struct dagu_proc_ns_operations *dagu_ipc_proc_operations(void);

#endif
