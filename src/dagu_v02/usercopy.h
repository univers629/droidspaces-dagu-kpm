/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_USERCOPY_H
#define DAGU_V02_USERCOPY_H

int dagu_usercopy_bind(void);
unsigned long dagu_copy_from_user(void *to, const void *from, unsigned long size);
unsigned long dagu_copy_to_user(void *to, const void *from, unsigned long size);

#endif
