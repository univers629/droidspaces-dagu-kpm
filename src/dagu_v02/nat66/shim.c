/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel symbol shims for the IPv6 NAT KPM.
 *
 * KernelPatch resolves imports from its own symbol table only, which contains
 * nothing but KernelPatch's exports, so a KPM cannot link against arbitrary
 * kernel functions. Everything the netfilter sources call is therefore routed
 * through a pointer filled from kallsyms_lookup_name() when the module loads.
 *
 * The netfilter sources are compiled with -D<name>=ds_sym_<name>, which also
 * renames the prototype each kernel header provides; the wrappers below have
 * to match those prototypes exactly, and the static assertions fail the build
 * if one drifts.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <net/secure_seq.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_conntrack_core.h>

extern unsigned long ds_kp_lookup(const char *name);

/* The one data symbol the netfilter sources use directly. */
struct net *ds_nat66_init_net;

/* ------------------------------------------------------------------ shims -- */

static typeof(&kfree) p_kfree;
void ds_sym_kfree(const void *objp) { p_kfree(objp); }
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_kfree), __typeof__(kfree)), "kfree");

static typeof(&dst_release) p_dst_release;
void ds_sym_dst_release(struct dst_entry *dst) { p_dst_release(dst); }
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_dst_release), __typeof__(dst_release)), "dst_release");

static typeof(&csum_ipv6_magic) p_csum_ipv6_magic;
__sum16 ds_sym_csum_ipv6_magic(const struct in6_addr *saddr,
			       const struct in6_addr *daddr, __u32 len,
			       __u8 proto, __wsum sum)
{
	return p_csum_ipv6_magic(saddr, daddr, len, proto, sum);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_csum_ipv6_magic), __typeof__(csum_ipv6_magic)), "csum_ipv6_magic");

static typeof(&inet_proto_csum_replace4) p_inet_proto_csum_replace4;
void ds_sym_inet_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb,
				     __be32 from, __be32 to, bool pseudohdr)
{
	p_inet_proto_csum_replace4(sum, skb, from, to, pseudohdr);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_inet_proto_csum_replace4), __typeof__(inet_proto_csum_replace4)), "inet_proto_csum_replace4");

static typeof(&inet_proto_csum_replace16) p_inet_proto_csum_replace16;
void ds_sym_inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
				      const __be32 *from, const __be32 *to,
				      bool pseudohdr)
{
	p_inet_proto_csum_replace16(sum, skb, from, to, pseudohdr);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_inet_proto_csum_replace16), __typeof__(inet_proto_csum_replace16)), "inet_proto_csum_replace16");

static typeof(&ip6_route_me_harder) p_ip6_route_me_harder;
int ds_sym_ip6_route_me_harder(struct net *net, struct sk_buff *skb)
{
	return p_ip6_route_me_harder(net, skb);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ip6_route_me_harder), __typeof__(ip6_route_me_harder)), "ip6_route_me_harder");

static typeof(&ip6t_alloc_initial_table) p_ip6t_alloc_initial_table;
void *ds_sym_ip6t_alloc_initial_table(const struct xt_table *table)
{
	return p_ip6t_alloc_initial_table(table);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ip6t_alloc_initial_table), __typeof__(ip6t_alloc_initial_table)), "ip6t_alloc_initial_table");

static typeof(&ip6t_do_table) p_ip6t_do_table;
unsigned int ds_sym_ip6t_do_table(struct sk_buff *skb,
				  const struct nf_hook_state *state,
				  struct xt_table *table)
{
	return p_ip6t_do_table(skb, state, table);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ip6t_do_table), __typeof__(ip6t_do_table)), "ip6t_do_table");

static typeof(&ip6t_register_table) p_ip6t_register_table;
int ds_sym_ip6t_register_table(struct net *net, const struct xt_table *table,
			       const struct ip6t_replace *repl,
			       const struct nf_hook_ops *ops,
			       struct xt_table **res)
{
	return p_ip6t_register_table(net, table, repl, ops, res);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ip6t_register_table), __typeof__(ip6t_register_table)), "ip6t_register_table");

static typeof(&ip6t_unregister_table) p_ip6t_unregister_table;
void ds_sym_ip6t_unregister_table(struct net *net, struct xt_table *table,
				  const struct nf_hook_ops *ops)
{
	p_ip6t_unregister_table(net, table, ops);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ip6t_unregister_table), __typeof__(ip6t_unregister_table)), "ip6t_unregister_table");

static typeof(&ipv6_dev_get_saddr) p_ipv6_dev_get_saddr;
int ds_sym_ipv6_dev_get_saddr(struct net *net, const struct net_device *dev,
			      const struct in6_addr *daddr, unsigned int srcprefs,
			      struct in6_addr *saddr)
{
	return p_ipv6_dev_get_saddr(net, dev, daddr, srcprefs, saddr);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ipv6_dev_get_saddr), __typeof__(ipv6_dev_get_saddr)), "ipv6_dev_get_saddr");

static typeof(&ipv6_skip_exthdr) p_ipv6_skip_exthdr;
int ds_sym_ipv6_skip_exthdr(const struct sk_buff *skb, int start, u8 *nexthdrp,
			    __be16 *frag_offp)
{
	return p_ipv6_skip_exthdr(skb, start, nexthdrp, frag_offp);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_ipv6_skip_exthdr), __typeof__(ipv6_skip_exthdr)), "ipv6_skip_exthdr");

static typeof(&nf_ct_invert_tuplepr) p_nf_ct_invert_tuplepr;
bool ds_sym_nf_ct_invert_tuplepr(struct nf_conntrack_tuple *inverse,
				 const struct nf_conntrack_tuple *orig)
{
	return p_nf_ct_invert_tuplepr(inverse, orig);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_ct_invert_tuplepr), __typeof__(nf_ct_invert_tuplepr)), "nf_ct_invert_tuplepr");

static typeof(&nf_ct_nat_ext_add) p_nf_ct_nat_ext_add;
struct nf_conn_nat *ds_sym_nf_ct_nat_ext_add(struct nf_conn *ct)
{
	return p_nf_ct_nat_ext_add(ct);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_ct_nat_ext_add), __typeof__(nf_ct_nat_ext_add)), "nf_ct_nat_ext_add");

static typeof(&nf_ct_netns_get) p_nf_ct_netns_get;
int ds_sym_nf_ct_netns_get(struct net *net, u8 nfproto)
{
	return p_nf_ct_netns_get(net, nfproto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_ct_netns_get), __typeof__(nf_ct_netns_get)), "nf_ct_netns_get");

static typeof(&nf_ct_netns_put) p_nf_ct_netns_put;
void ds_sym_nf_ct_netns_put(struct net *net, u8 nfproto)
{
	p_nf_ct_netns_put(net, nfproto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_ct_netns_put), __typeof__(nf_ct_netns_put)), "nf_ct_netns_put");

static typeof(&nf_ip6_checksum) p_nf_ip6_checksum;
__sum16 ds_sym_nf_ip6_checksum(struct sk_buff *skb, unsigned int hook,
			       unsigned int dataoff, u8 protocol)
{
	return p_nf_ip6_checksum(skb, hook, dataoff, protocol);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_ip6_checksum), __typeof__(nf_ip6_checksum)), "nf_ip6_checksum");

static typeof(&nf_nat_inet_fn) p_nf_nat_inet_fn;
unsigned int ds_sym_nf_nat_inet_fn(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	return p_nf_nat_inet_fn(priv, skb, state);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_inet_fn), __typeof__(nf_nat_inet_fn)), "nf_nat_inet_fn");

static typeof(&nf_nat_l3proto_register) p_nf_nat_l3proto_register;
int ds_sym_nf_nat_l3proto_register(const struct nf_nat_l3proto *l3proto)
{
	return p_nf_nat_l3proto_register(l3proto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_l3proto_register), __typeof__(nf_nat_l3proto_register)), "nf_nat_l3proto_register");

static typeof(&nf_nat_l3proto_unregister) p_nf_nat_l3proto_unregister;
void ds_sym_nf_nat_l3proto_unregister(const struct nf_nat_l3proto *l3proto)
{
	p_nf_nat_l3proto_unregister(l3proto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_l3proto_unregister), __typeof__(nf_nat_l3proto_unregister)), "nf_nat_l3proto_unregister");

static typeof(&__nf_nat_l4proto_find) p___nf_nat_l4proto_find;
const struct nf_nat_l4proto *ds_sym___nf_nat_l4proto_find(u8 l3proto, u8 l4proto)
{
	return p___nf_nat_l4proto_find(l3proto, l4proto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym___nf_nat_l4proto_find), __typeof__(__nf_nat_l4proto_find)), "__nf_nat_l4proto_find");

static typeof(&nf_nat_l4proto_nlattr_to_range) p_nf_nat_l4proto_nlattr_to_range;
int ds_sym_nf_nat_l4proto_nlattr_to_range(struct nlattr *tb[],
					  struct nf_nat_range2 *range)
{
	return p_nf_nat_l4proto_nlattr_to_range(tb, range);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_l4proto_nlattr_to_range), __typeof__(nf_nat_l4proto_nlattr_to_range)), "nf_nat_l4proto_nlattr_to_range");

static typeof(&nf_nat_l4proto_register) p_nf_nat_l4proto_register;
int ds_sym_nf_nat_l4proto_register(u8 l3proto, const struct nf_nat_l4proto *l4proto)
{
	return p_nf_nat_l4proto_register(l3proto, l4proto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_l4proto_register), __typeof__(nf_nat_l4proto_register)), "nf_nat_l4proto_register");

static typeof(&nf_nat_l4proto_unregister) p_nf_nat_l4proto_unregister;
void ds_sym_nf_nat_l4proto_unregister(u8 l3proto, const struct nf_nat_l4proto *l4proto)
{
	p_nf_nat_l4proto_unregister(l3proto, l4proto);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_l4proto_unregister), __typeof__(nf_nat_l4proto_unregister)), "nf_nat_l4proto_unregister");

static typeof(&nf_nat_register_fn) p_nf_nat_register_fn;
int ds_sym_nf_nat_register_fn(struct net *net, const struct nf_hook_ops *ops,
			      const struct nf_hook_ops *nat_ops,
			      unsigned int ops_count)
{
	return p_nf_nat_register_fn(net, ops, nat_ops, ops_count);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_register_fn), __typeof__(nf_nat_register_fn)), "nf_nat_register_fn");

static typeof(&nf_nat_setup_info) p_nf_nat_setup_info;
unsigned int ds_sym_nf_nat_setup_info(struct nf_conn *ct,
				      const struct nf_nat_range2 *range,
				      enum nf_nat_manip_type maniptype)
{
	return p_nf_nat_setup_info(ct, range, maniptype);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_setup_info), __typeof__(nf_nat_setup_info)), "nf_nat_setup_info");

static typeof(&nf_nat_unregister_fn) p_nf_nat_unregister_fn;
void ds_sym_nf_nat_unregister_fn(struct net *net, const struct nf_hook_ops *ops,
				 unsigned int ops_count)
{
	p_nf_nat_unregister_fn(net, ops, ops_count);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_unregister_fn), __typeof__(nf_nat_unregister_fn)), "nf_nat_unregister_fn");

static typeof(&nf_nat_used_tuple) p_nf_nat_used_tuple;
int ds_sym_nf_nat_used_tuple(const struct nf_conntrack_tuple *tuple,
			     const struct nf_conn *ct)
{
	return p_nf_nat_used_tuple(tuple, ct);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_nat_used_tuple), __typeof__(nf_nat_used_tuple)), "nf_nat_used_tuple");

static typeof(&nf_xfrm_me_harder) p_nf_xfrm_me_harder;
int ds_sym_nf_xfrm_me_harder(struct net *net, struct sk_buff *skb, unsigned int family)
{
	return p_nf_xfrm_me_harder(net, skb, family);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nf_xfrm_me_harder), __typeof__(nf_xfrm_me_harder)), "nf_xfrm_me_harder");

static typeof(&nla_memcpy) p_nla_memcpy;
int ds_sym_nla_memcpy(void *dest, const struct nlattr *src, int count)
{
	return p_nla_memcpy(dest, src, count);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_nla_memcpy), __typeof__(nla_memcpy)), "nla_memcpy");

static typeof(&register_pernet_subsys) p_register_pernet_subsys;
int ds_sym_register_pernet_subsys(struct pernet_operations *ops)
{
	return p_register_pernet_subsys(ops);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_register_pernet_subsys), __typeof__(register_pernet_subsys)), "register_pernet_subsys");

static typeof(&unregister_pernet_subsys) p_unregister_pernet_subsys;
void ds_sym_unregister_pernet_subsys(struct pernet_operations *ops)
{
	p_unregister_pernet_subsys(ops);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_unregister_pernet_subsys), __typeof__(unregister_pernet_subsys)), "unregister_pernet_subsys");

static typeof(&secure_ipv6_port_ephemeral) p_secure_ipv6_port_ephemeral;
u32 ds_sym_secure_ipv6_port_ephemeral(const __be32 *saddr, const __be32 *daddr,
				      __be16 dport)
{
	return p_secure_ipv6_port_ephemeral(saddr, daddr, dport);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_secure_ipv6_port_ephemeral), __typeof__(secure_ipv6_port_ephemeral)), "secure_ipv6_port_ephemeral");

static typeof(&skb_checksum) p_skb_checksum;
__wsum ds_sym_skb_checksum(const struct sk_buff *skb, int offset, int len,
			   __wsum csum)
{
	return p_skb_checksum(skb, offset, len, csum);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_skb_checksum), __typeof__(skb_checksum)), "skb_checksum");

static typeof(&skb_make_writable) p_skb_make_writable;
int ds_sym_skb_make_writable(struct sk_buff *skb, unsigned int writable_len)
{
	return p_skb_make_writable(skb, writable_len);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_skb_make_writable), __typeof__(skb_make_writable)), "skb_make_writable");

static typeof(&xt_register_target) p_xt_register_target;
int ds_sym_xt_register_target(struct xt_target *target)
{
	return p_xt_register_target(target);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_xt_register_target), __typeof__(xt_register_target)), "xt_register_target");

static typeof(&xt_unregister_target) p_xt_unregister_target;
void ds_sym_xt_unregister_target(struct xt_target *target)
{
	p_xt_unregister_target(target);
}
_Static_assert(__builtin_types_compatible_p(__typeof__(ds_sym_xt_unregister_target), __typeof__(xt_unregister_target)), "xt_unregister_target");

/* WARN_ON is the only user. Diagnostics from these paths are dropped rather
 * than forwarding a variadic call that C cannot express. */
int ds_sym_printk(const char *fmt, ...)
{
	return 0;
}

/* The netfilter sources build without libc; these two are compiler calls. */
int memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *a = cs, *b = ct;
	while (count--) {
		if (*a != *b)
			return (int)*a - (int)*b;
		a++;
		b++;
	}
	return 0;
}

/* -------------------------------------------------------------- resolution -- */

static const struct {
	const char *name;
	void **slot;
} shims[] = {
	{ "kfree", (void **)&p_kfree },
	{ "dst_release", (void **)&p_dst_release },
	{ "csum_ipv6_magic", (void **)&p_csum_ipv6_magic },
	{ "inet_proto_csum_replace4", (void **)&p_inet_proto_csum_replace4 },
	{ "inet_proto_csum_replace16", (void **)&p_inet_proto_csum_replace16 },
	{ "ip6_route_me_harder", (void **)&p_ip6_route_me_harder },
	{ "ip6t_alloc_initial_table", (void **)&p_ip6t_alloc_initial_table },
	{ "ip6t_do_table", (void **)&p_ip6t_do_table },
	{ "ip6t_register_table", (void **)&p_ip6t_register_table },
	{ "ip6t_unregister_table", (void **)&p_ip6t_unregister_table },
	{ "ipv6_dev_get_saddr", (void **)&p_ipv6_dev_get_saddr },
	{ "ipv6_skip_exthdr", (void **)&p_ipv6_skip_exthdr },
	{ "nf_ct_invert_tuplepr", (void **)&p_nf_ct_invert_tuplepr },
	{ "nf_ct_nat_ext_add", (void **)&p_nf_ct_nat_ext_add },
	{ "nf_ct_netns_get", (void **)&p_nf_ct_netns_get },
	{ "nf_ct_netns_put", (void **)&p_nf_ct_netns_put },
	{ "nf_ip6_checksum", (void **)&p_nf_ip6_checksum },
	{ "nf_nat_inet_fn", (void **)&p_nf_nat_inet_fn },
	{ "nf_nat_l3proto_register", (void **)&p_nf_nat_l3proto_register },
	{ "nf_nat_l3proto_unregister", (void **)&p_nf_nat_l3proto_unregister },
	{ "__nf_nat_l4proto_find", (void **)&p___nf_nat_l4proto_find },
	{ "nf_nat_l4proto_nlattr_to_range", (void **)&p_nf_nat_l4proto_nlattr_to_range },
	{ "nf_nat_l4proto_register", (void **)&p_nf_nat_l4proto_register },
	{ "nf_nat_l4proto_unregister", (void **)&p_nf_nat_l4proto_unregister },
	{ "nf_nat_register_fn", (void **)&p_nf_nat_register_fn },
	{ "nf_nat_setup_info", (void **)&p_nf_nat_setup_info },
	{ "nf_nat_unregister_fn", (void **)&p_nf_nat_unregister_fn },
	{ "nf_nat_used_tuple", (void **)&p_nf_nat_used_tuple },
	{ "nf_xfrm_me_harder", (void **)&p_nf_xfrm_me_harder },
	{ "nla_memcpy", (void **)&p_nla_memcpy },
	{ "register_pernet_subsys", (void **)&p_register_pernet_subsys },
	{ "unregister_pernet_subsys", (void **)&p_unregister_pernet_subsys },
	{ "secure_ipv6_port_ephemeral", (void **)&p_secure_ipv6_port_ephemeral },
	{ "skb_checksum", (void **)&p_skb_checksum },
	{ "skb_make_writable", (void **)&p_skb_make_writable },
	{ "xt_register_target", (void **)&p_xt_register_target },
	{ "xt_unregister_target", (void **)&p_xt_unregister_target },
	{ "init_net", (void **)&ds_nat66_init_net },
};

long ds_nat66_sym_init(void)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(shims); i++) {
		unsigned long addr = ds_kp_lookup(shims[i].name);

		if (!addr) {
			printk("ds-nat66: missing kernel symbol: %s\n", shims[i].name);
			return -2;
		}
		*shims[i].slot = (void *)addr;
	}
	return 0;
}
