/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KernelPatch exports kallsyms_lookup_name as a function pointer, which
 * conflicts with the kernel header's function declaration. This small
 * translation unit is compiled against the KernelPatch headers only and
 * wraps it for the shim table.
 */

#include <kallsyms.h>

unsigned long ds_kp_lookup(const char *name)
{
	return kallsyms_lookup_name(name);
}
