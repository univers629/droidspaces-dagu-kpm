/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IPv6 MASQUERADE target for a kernel built without
 * CONFIG_IP6_NF_TARGET_MASQUERADE.
 *
 * The IPv4 target (ipt_MASQUERADE.c) registers NFPROTO_IPV4, so ip6tables
 * cannot resolve "MASQUERADE" even when the IPv6 nat table exists. This
 * registers the same target name for NFPROTO_IPV6, with the payload size the
 * older IPv6 target used: struct nf_nat_range. Droidspaces builds its
 * MASQUERADE rule by hand and sends exactly that size.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/ipv6/nf_nat_masquerade.h>


static int masq6_tg_check(const struct xt_tgchk_param *par)
{
	const struct nf_nat_range *range = par->targinfo;

	if (range->flags & NF_NAT_RANGE_MAP_IPS)
		return -EINVAL;

	return nf_ct_netns_get(par->net, par->family);
}

static unsigned int masq6_tg(struct sk_buff *skb,
			     const struct xt_action_param *par)
{
	const struct nf_nat_range *old = par->targinfo;
	struct nf_nat_range2 range;

	memset(&range, 0, sizeof(range));
	range.flags = old->flags;
	range.min_addr = old->min_addr;
	range.max_addr = old->max_addr;
	range.min_proto = old->min_proto;
	range.max_proto = old->max_proto;

	return nf_nat_masquerade_ipv6(skb, &range, xt_out(par));
}

static void masq6_tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static struct xt_target masq6_tg_reg __read_mostly = {
	.name		= "MASQUERADE",
	.family		= NFPROTO_IPV6,
	.target		= masq6_tg,
	.targetsize	= sizeof(struct nf_nat_range),
	.table		= "nat",
	.hooks		= 1 << NF_INET_POST_ROUTING,
	.checkentry	= masq6_tg_check,
	.destroy	= masq6_tg_destroy,
	.me		= NULL,
};

int ds_nat66_target_init(void)
{
	int ret = xt_register_target(&masq6_tg_reg);

	if (ret)
		return ret;

	ret = nf_nat_masquerade_ipv6_register_notifier();
	if (ret)
		xt_unregister_target(&masq6_tg_reg);

	return ret;
}

void ds_nat66_target_exit(void)
{
	nf_nat_masquerade_ipv6_unregister_notifier();
	xt_unregister_target(&masq6_tg_reg);
}
