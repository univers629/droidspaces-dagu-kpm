/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_PROC_BRIDGE_H
#define DAGU_V02_PROC_BRIDGE_H

/* The operations objects and their callbacks are owned by the caller. */
int dagu_proc_bridge_install(const void *pid_ops, const void *pid_children_ops,
                             const void *ipc_ops);
void dagu_proc_bridge_uninstall(void);

#endif
