/* SPDX-License-Identifier: GPL-2.0-only */
/* Selected current-boot offsets. Inferred fields require more proof before use. */
#ifndef DAGU_V02_ABI_H
#define DAGU_V02_ABI_H

#include <stdint.h>

/* Exact GFP_KERNEL immediate observed in the current boot's alloc_pid path. */
#define DAGU_GFP_KERNEL                0x006000c0U

#define DAGU_TASK_USAGE                 0x68U
#define DAGU_TASK_THREAD_PID            0x6a0U
#define DAGU_TASK_CRED                  0x7e8U
#define DAGU_CRED_USER_NS               0x88U
#define DAGU_TASK_NSPROXY               0x818U

#define DAGU_NSPROXY_IPC                0x10U
#define DAGU_NSPROXY_MNT                0x18U
#define DAGU_NSPROXY_PID_CHILDREN       0x20U

#define DAGU_PIDNS_KREF                 0x00U
#define DAGU_PIDNS_IDR                  0x08U
#define DAGU_PIDNS_ALLOCATED            0x30U
#define DAGU_PIDNS_CHILD_REAPER         0x38U
#define DAGU_PIDNS_CACHE                0x40U
#define DAGU_PIDNS_LEVEL                0x48U
#define DAGU_PIDNS_PARENT               0x50U
#define DAGU_PIDNS_PROC_MNT             0x58U
#define DAGU_INFERRED_PIDNS_REBOOT      0xb8U /* derived from Android 4.19 layout */
#define DAGU_INFERRED_PIDNS_USER_NS     0x70U
#define DAGU_INFERRED_PIDNS_UCOUNTS     0x78U
#define DAGU_PIDNS_PROC_WORK            0x80U
#define DAGU_INFERRED_PIDNS_NS_COMMON   0xc0U
#define DAGU_PIDNS_INUM                 0xd0U
#define DAGU_PIDNS_IDR_GFP_MASK         0x0cU
#define DAGU_PIDNS_OWNER_USER_NS        0x70U
#define DAGU_PIDNS_NS_COMMON           0xc0U

#define DAGU_PID_COUNT                  0x00U
#define DAGU_PID_LEVEL                  0x04U
#define DAGU_PID_RCU_HEAD               0x40U
#define DAGU_PID_FIRST_UPID             0x50U
#define DAGU_UPID_NR                    0x00U
#define DAGU_UPID_NS                    0x08U

#define DAGU_FILE_INODE                 0x20U
#define DAGU_PROC_INODE_PID_BACK        0x48U
#define DAGU_DIR_CONTEXT_POS            0x08U
#define DAGU_DENTRY_NAME_LEN            0x24U
#define DAGU_DENTRY_NAME_PTR            0x28U

/* Target 4.19.157 proc_dir_entry fields verified in live proc_register code. */
#define DAGU_PROC_DIR_SUBDIR_ROOT       0x80U
#define DAGU_PROC_SUBDIR_NODE           0x88U
#define DAGU_PROC_RB_LEFT               0x08U
#define DAGU_PROC_RB_RIGHT              0x10U
#define DAGU_PROC_NODE_NAME             0x18U
#define DAGU_PROC_NODE_NAME_LEN         0x22U
#define DAGU_PROC_ENTRY_FOPS            0x30U

/* These only model fields directly accessed by the KPM. */
static inline void *dagu_load_ptr(const void *base, unsigned int offset)
{
    return *(void *const volatile *)((const unsigned char *)base + offset);
}

static inline unsigned int dagu_load_u32(const void *base, unsigned int offset)
{
    return *(const volatile unsigned int *)((const unsigned char *)base + offset);
}

static inline void dagu_store_ptr(void *base, unsigned int offset, void *value)
{
    *(void *volatile *)((unsigned char *)base + offset) = value;
}

static inline void dagu_store_u32(void *base, unsigned int offset, unsigned int value)
{
    *(volatile unsigned int *)((unsigned char *)base + offset) = value;
}

#endif
