/* SPDX-License-Identifier: GPL-2.0-only */
/* A deliberately conservative ARM64 user-pointer gate for the raw copy ABI. */

#include "usercopy.h"

#include <kallsyms.h>
#include <stdint.h>

typedef unsigned long (*copy_fn)(void *, const void *, unsigned long);

static copy_fn raw_from_user;
static copy_fn raw_to_user;

static int checked_user_range(const void *pointer, unsigned long size)
{
    uintptr_t address = (uintptr_t)pointer;
    /* Reject tagged pointers until the current boot's tagged-address ABI is
     * proved. This bound is conservative for Android arm64 user mappings and
     * excludes the high-half kernel mapping even if set_fs(KERNEL_DS) is active.
     */
    const uintptr_t bound = (uintptr_t)1U << 47;
    if (address >= bound || size > bound - address)
        return 0;
    /* __arch_copy_{from,to}_user does no access_ok and ARM64's raw_copy
     * normally masks the pointer. A speculation barrier follows the check.
     */
    __asm__ volatile("csdb" ::: "memory");
    return 1;
}

int dagu_usercopy_bind(void)
{
    raw_from_user = (copy_fn)kallsyms_lookup_name("__arch_copy_from_user");
    raw_to_user = (copy_fn)kallsyms_lookup_name("__arch_copy_to_user");
    return raw_from_user && raw_to_user ? 0 : -2;
}

unsigned long dagu_copy_from_user(void *to, const void *from, unsigned long size)
{
    if (!size)
        return 0;
    if (!raw_from_user || !checked_user_range(from, size))
        return size;
    return raw_from_user(to, from, size);
}

unsigned long dagu_copy_to_user(void *to, const void *from, unsigned long size)
{
    if (!size)
        return 0;
    if (!raw_to_user || !checked_user_range(to, size))
        return size;
    return raw_to_user(to, from, size);
}
