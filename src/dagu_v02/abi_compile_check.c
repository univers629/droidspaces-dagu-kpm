/* SPDX-License-Identifier: GPL-2.0-only */
/* Host-only compile check for the current offset accessors. */
#include "abi.h"
#include "ns_types.h"
#include "msg_uapi.h"

struct dagu_android_work_struct_model {
    uint64_t data;
    void *entry[2];
    void *func;
    uint64_t android_kabi_reserved1;
    uint64_t android_kabi_reserved2;
};

_Static_assert(sizeof(struct dagu_android_work_struct_model) == 0x30U,
               "Android 4.19 work_struct reserve layout changed");
_Static_assert(DAGU_INFERRED_PIDNS_REBOOT ==
               DAGU_PIDNS_PROC_WORK + sizeof(struct dagu_android_work_struct_model) +
               2U * sizeof(uint32_t),
               "pid_namespace reboot offset derivation changed");
_Static_assert(DAGU_PIDNS_NS_COMMON ==
               ((DAGU_PIDNS_PROC_WORK + sizeof(struct dagu_android_work_struct_model) +
                 3U * sizeof(uint32_t) + 7U) & ~7U),
               "pid_namespace ns_common adjacency changed");

void dagu_abi_compile_check(void *base)
{
    dagu_store_ptr(base, DAGU_NSPROXY_IPC,
                   dagu_load_ptr(base, DAGU_NSPROXY_PID_CHILDREN));
    dagu_store_u32(base, DAGU_PIDNS_ALLOCATED,
                   dagu_load_u32(base, DAGU_PIDNS_LEVEL));
    dagu_store_u32(base, DAGU_INFERRED_PIDNS_REBOOT,
                   dagu_load_u32(base, DAGU_INFERRED_PIDNS_REBOOT));
}
