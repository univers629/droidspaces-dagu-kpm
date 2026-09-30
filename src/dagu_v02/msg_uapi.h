/* SPDX-License-Identifier: GPL-2.0-only */
/* ARM64 Linux SysV message ABI as used by Android bionic. */
#ifndef DAGU_V02_MSG_UAPI_H
#define DAGU_V02_MSG_UAPI_H

#include <stdint.h>

struct dagu_ipc64_perm {
    int32_t key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint16_t mode;
    uint16_t pad1;
    uint16_t seq;
    uint16_t pad2;
    uint64_t unused1;
    uint64_t unused2;
};

struct dagu_msqid64_ds {
    struct dagu_ipc64_perm msg_perm;
    int64_t msg_stime;
    int64_t msg_rtime;
    int64_t msg_ctime;
    uint64_t msg_cbytes;
    uint64_t msg_qnum;
    uint64_t msg_qbytes;
    int32_t msg_lspid;
    int32_t msg_lrpid;
    uint64_t unused4;
    uint64_t unused5;
};

_Static_assert(sizeof(struct dagu_ipc64_perm) == 48, "unexpected ARM64 IPC permission ABI");
_Static_assert(sizeof(struct dagu_msqid64_ds) == 120, "unexpected ARM64 message queue ABI");

#define DAGU_IPC_CREAT 0x200
#define DAGU_IPC_EXCL 0x400
#define DAGU_IPC_NOWAIT 0x800
#define DAGU_IPC_RMID 0
#define DAGU_IPC_SET 1
#define DAGU_IPC_STAT 2
#define DAGU_IPC_64 0x100
#define DAGU_MSG_NOERROR 0x1000
#define DAGU_MSG_EXCEPT 0x2000
#define DAGU_MSG_COPY 0x4000

#endif
