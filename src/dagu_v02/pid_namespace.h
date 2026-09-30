/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_PID_NAMESPACE_H
#define DAGU_V02_PID_NAMESPACE_H

#include "ns_types.h"

int dagu_pid_namespace_bind(void);
void dagu_pid_namespace_unbind(void);
void *dagu_pid_namespace_create(void *parent, void *user_ns);
void dagu_pid_namespace_get(void *ns);
void dagu_pid_namespace_put(void *ns);
const struct dagu_proc_ns_operations *dagu_pid_proc_operations(void);
const struct dagu_proc_ns_operations *dagu_pid_children_proc_operations(void);
void *dagu_pid_root(void);

#endif
