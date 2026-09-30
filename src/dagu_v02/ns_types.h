/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_NS_TYPES_H
#define DAGU_V02_NS_TYPES_H

#include <stdint.h>

struct dagu_ns_common;

struct dagu_proc_ns_operations {
    const char *name;
    const char *real_ns_name;
    int type;
    int padding;
    struct dagu_ns_common *(*get)(void *task);
    void (*put)(struct dagu_ns_common *ns);
    int (*install)(void *nsproxy, struct dagu_ns_common *ns);
    void *(*owner)(struct dagu_ns_common *ns);
    struct dagu_ns_common *(*get_parent)(struct dagu_ns_common *ns);
};

struct dagu_ns_common {
    unsigned long stashed;
    const struct dagu_proc_ns_operations *ops;
    unsigned int inum;
    unsigned int padding;
};

_Static_assert(__builtin_offsetof(struct dagu_proc_ns_operations, type) == 16,
               "proc operations type offset differs from current Image");
_Static_assert(__builtin_offsetof(struct dagu_proc_ns_operations, get) == 24,
               "proc operations callback offset differs from source ABI");
_Static_assert(__builtin_offsetof(struct dagu_ns_common, inum) == 16,
               "namespace inode offset differs from root object evidence");

#define DAGU_CLONE_NEWIPC 0x08000000UL
#define DAGU_CLONE_NEWPID 0x20000000UL

#endif
