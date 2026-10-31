/*
 * Copyright (c) 2011 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Based on Rusty Russell's IPv6 MASQUERADE target. Development of IPv6
 * NAT funded by Astaro.
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_nat.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/netfilter/ipv6/nf_nat_masquerade.h>

#define MAX_WORK_COUNT	16

static atomic_t v6_worker_count;

unsigned int
nf_nat_masquerade_ipv6(struct sk_buff *skb, const struct nf_nat_range2 *range,
		       const struct net_device *out)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	struct in6_addr src;
	struct nf_conn *ct;
	struct nf_nat_range2 newrange;

	ct = nf_ct_get(skb, &ctinfo);
	if (!(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
		     ctinfo == IP_CT_RELATED_REPLY)))
		return NF_DROP;

	if (ipv6_dev_get_saddr(nf_ct_net(ct), out,
			       &ipv6_hdr(skb)->daddr, 0, &src) < 0)
		return NF_DROP;

	nat = nf_ct_nat_ext_add(ct);
	if (nat)
		nat->masq_index = out->ifindex;

	newrange.flags		= range->flags | NF_NAT_RANGE_MAP_IPS;
	newrange.min_addr.in6	= src;
	newrange.max_addr.in6	= src;
	newrange.min_proto	= range->min_proto;
	newrange.max_proto	= range->max_proto;

	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
}

/*
 * The device/gateway notifications only purge conntrack entries when an
 * interface or address goes away. They need nf_ct_iterate_cleanup_net() and
 * __put_net(), neither of which this kernel exports, so they are left out;
 * entries still expire on their own. The entry points stay, as no-ops, for
 * the target's init and exit paths.
 */
int nf_nat_masquerade_ipv6_register_notifier(void)
{
	return 0;
}

void nf_nat_masquerade_ipv6_unregister_notifier(void)
{
}
