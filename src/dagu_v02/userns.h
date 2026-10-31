/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DAGU_V02_USERNS_H
#define DAGU_V02_USERNS_H

int dagu_userns_bind(void);
int dagu_userns_install(void);
void dagu_userns_uninstall(void);
unsigned int dagu_userns_live(void);
int dagu_userns_is_record(void *ns);

int dagu_userns_proc_bind(void);
int dagu_userns_proc_install(void);
void dagu_userns_proc_uninstall(void);

#endif
