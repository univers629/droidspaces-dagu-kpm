/* SPDX-License-Identifier: GPL-2.0-only */
/* Compare our kernel-side SysV message structures to the Android ARM64 UAPI. */
#include <stddef.h>
#include <asm/msgbuf.h>
#include <asm/ipcbuf.h>
#include "msg_uapi.h"

#define SAME_SIZE(a, b) _Static_assert(sizeof(a) == sizeof(b), "size mismatch")
#define SAME_FIELD(a, b, field) \
    _Static_assert(offsetof(a, field) == offsetof(b, field), "field offset mismatch")

SAME_SIZE(struct dagu_ipc64_perm, struct ipc64_perm);
SAME_SIZE(struct dagu_msqid64_ds, struct msqid64_ds);
SAME_FIELD(struct dagu_ipc64_perm, struct ipc64_perm, key);
SAME_FIELD(struct dagu_ipc64_perm, struct ipc64_perm, uid);
SAME_FIELD(struct dagu_ipc64_perm, struct ipc64_perm, mode);
SAME_FIELD(struct dagu_ipc64_perm, struct ipc64_perm, seq);
SAME_FIELD(struct dagu_msqid64_ds, struct msqid64_ds, msg_perm);
SAME_FIELD(struct dagu_msqid64_ds, struct msqid64_ds, msg_stime);
SAME_FIELD(struct dagu_msqid64_ds, struct msqid64_ds, msg_ctime);
SAME_FIELD(struct dagu_msqid64_ds, struct msqid64_ds, msg_qbytes);
SAME_FIELD(struct dagu_msqid64_ds, struct msqid64_ds, msg_lrpid);
