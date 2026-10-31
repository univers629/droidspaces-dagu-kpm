/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IPv6 NAT for a kernel built without CONFIG_IP6_NF_NAT and without an IPv6
 * MASQUERADE target.
 *
 * The netfilter sources under nat66/ are the kernel's own, compiled against
 * the matching 4.19.157 headers. Every kernel symbol they call goes through
 * shim.c, because KernelPatch resolves imports from its own table only.
 *
 * Registration is deferred to a kernel thread: the KPM loads at
 * pre-kernel-init, before netfilter allocates its per-family tables, and the
 * registration path blocks on locks that are held during early boot. A worker
 * that runs later keeps a blocked registration from delaying boot.
 */

#include "nat66.h"

#include <kallsyms.h>
#include <log.h>

#define DAGU_NAT66_DELAY_MS 10000U

extern unsigned long ds_kp_lookup(const char *name);

long ds_nat66_sym_init(void);
int ds_nat66_l3proto_init(void);
int ds_nat66_target_init(void);
int ds_nat66_table_init(void);

static void (*ds_msleep)(unsigned int msecs);
static void *(*ds_kthread_create)(int (*fn)(void *), void *data, int node,
                                  const char *name);
static int (*ds_wake_up_process)(void *task);

static int dagu_nat66_worker(void *unused)
{
    (void)unused;

    if (ds_msleep)
        ds_msleep(DAGU_NAT66_DELAY_MS);

    if (ds_nat66_l3proto_init()) {
        logke("ds-dagu-nat66: l3proto registration failed\n");
        return 0;
    }
    if (ds_nat66_target_init()) {
        logke("ds-dagu-nat66: MASQUERADE target registration failed\n");
        return 0;
    }
    if (ds_nat66_table_init()) {
        logke("ds-dagu-nat66: nat table registration failed\n");
        return 0;
    }
    logki("ds-dagu-nat66: IPv6 nat table and MASQUERADE target registered\n");
    return 0;
}

int dagu_nat66_bind(void)
{
    if (ds_nat66_sym_init())
        return -2;

    ds_msleep = (void *)ds_kp_lookup("msleep");
    ds_kthread_create = (void *)ds_kp_lookup("kthread_create_on_node");
    ds_wake_up_process = (void *)ds_kp_lookup("wake_up_process");
    if (!ds_kthread_create || !ds_wake_up_process)
        return -2;
    return 0;
}

int dagu_nat66_install(void)
{
    void *task = ds_kthread_create(dagu_nat66_worker, 0, -1, "ds-nat66");

    if (!task)
        return -1;
    ds_wake_up_process(task);
    logki("ds-dagu-nat66: registration queued\n");
    return 0;
}

void dagu_nat66_uninstall(void)
{
    /*
     * The nat table's hooks point into this image and the unload path is
     * already refused, so the registration is left in place.
     */
}
