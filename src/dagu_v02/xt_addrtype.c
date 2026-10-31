/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xt_addrtype match for a kernel built without
 * CONFIG_NETFILTER_XT_MATCH_ADDRTYPE.
 *
 * dockerd programs its NAT chain with
 *
 *   iptables --wait -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
 *
 * and aborts daemon startup when the match cannot be resolved. The image has
 * NETFILTER_XTABLES, the IPv4 table lookup that decides the address type
 * (inet_dev_addr_type), and the registration entry points, but not the match
 * that ties them together, so the match is registered here.
 *
 * Registration is deferred to the first xt_find_match() call. netfilter
 * allocates its per-family match lists in xt_init(), a module_init callable
 * that runs after this KPM's pre-kernel-init event, and the registration path
 * takes a mutex living inside that allocation. Registering during KPM init
 * dereferences a null table. xt_find_match() is what every iptables revision
 * probe and rule insertion reaches first, and it cannot run before xt_init(),
 * so the lookup that triggers registration is also the one that finds the new
 * match.
 *
 * The record layout and the field offsets used by the packet path belong to
 * this boot (4.19 arm64, CONFIG_COMPAT=y). They were read from the kernel's
 * own build headers; the assertions below fail the build if the record drifts,
 * and the packet path validates the pointers it dereferences before use.
 *
 * IPv6 is not covered. ipv6_addr_type, ipv6_anycast_destination and
 * __nf_ip6_route are all absent from this image, so both revisions are
 * registered for NFPROTO_IPV4 and ip6tables cannot resolve the name. The rules
 * that need this match are dockerd's IPv4 NAT rules.
 */

#include "xt_addrtype.h"

#include <hook.h>
#include <kallsyms.h>
#include <log.h>
#include <stdint.h>

/* ------------------------------------------------------------- constants -- */

#define DAGU_NFPROTO_IPV4		2U

#define DAGU_XT_ADDRTYPE_INVERT_SOURCE	0x0001U
#define DAGU_XT_ADDRTYPE_INVERT_DEST	0x0002U
#define DAGU_XT_ADDRTYPE_LIMIT_IFACE_IN	0x0004U
#define DAGU_XT_ADDRTYPE_LIMIT_IFACE_OUT 0x0008U

#define DAGU_NF_INET_PRE_ROUTING	0
#define DAGU_NF_INET_LOCAL_IN		1
#define DAGU_NF_INET_LOCAL_OUT		3
#define DAGU_NF_INET_POST_ROUTING	4

#define DAGU_EINVAL			22
#define DAGU_EAGAIN			11

/*
 * Pointers below this belong to userspace or to garbage. Every kernel address
 * on this target has the top sixteen bits set, so a value under the bound is
 * not one and must not be dereferenced.
 */
#define DAGU_KERNEL_ADDR_MIN		0xffff000000000000UL

/* sk_buff: head and network_header (verified against the target image). */
#define DAGU_SKB_HEAD			224U
#define DAGU_SKB_NETWORK_HEADER		196U

/* struct iphdr: source and destination address. */
#define DAGU_IPH_SADDR			12U
#define DAGU_IPH_DADDR			16U

#define DAGU_XT_NAME_LEN		29U

/* ------------------------------------------------------------ structures -- */

/* revision 0 match record */
struct dagu_xt_addrtype_info {
	uint16_t source;
	uint16_t dest;
	uint32_t invert_source;
	uint32_t invert_dest;
};

/* revision 1 match record */
struct dagu_xt_addrtype_info_v1 {
	uint16_t source;
	uint16_t dest;
	uint32_t flags;
};

struct dagu_nf_hook_state {
	uint32_t hook;
	uint8_t pf;
	uint8_t pad0[3];
	const void *in;
	const void *out;
	void *sk;
	void *net;
	void *okfn;
};

struct dagu_xt_action_param {
	void *match_or_target;
	void *matchinfo;
	const struct dagu_nf_hook_state *state;
	int fragoff;
	uint32_t thoff;
	uint8_t hotdrop;
};

struct dagu_xt_mtchk_param {
	void *net;
	const char *table;
	const void *entryinfo;
	const void *match;
	void *matchinfo;
	uint32_t hook_mask;
	uint8_t family;
	uint8_t nft_compat;
};

typedef int (*dagu_xt_match_fn)(const void *skb, struct dagu_xt_action_param *);
typedef int (*dagu_xt_check_fn)(const struct dagu_xt_mtchk_param *);

struct dagu_xt_match {
	void *list_next;
	void *list_prev;
	char name[DAGU_XT_NAME_LEN];
	uint8_t revision;
	uint8_t pad0[2];
	dagu_xt_match_fn match;
	dagu_xt_check_fn checkentry;
	void *destroy;
	void *compat_from_user;
	void *compat_to_user;
	void *me;
	const char *table;
	uint32_t matchsize;
	uint32_t usersize;
	uint32_t compatsize;
	uint32_t hooks;
	uint16_t proto;
	uint16_t family;
};

#define DAGU_ASSERT_OFF(field, want) \
	_Static_assert(__builtin_offsetof(struct dagu_xt_match, field) == (want), \
		       "xt_match." #field " offset changed")

DAGU_ASSERT_OFF(name, 0x10);
DAGU_ASSERT_OFF(revision, 0x2d);
DAGU_ASSERT_OFF(match, 0x30);
DAGU_ASSERT_OFF(checkentry, 0x38);
DAGU_ASSERT_OFF(me, 0x58);
DAGU_ASSERT_OFF(table, 0x60);
DAGU_ASSERT_OFF(matchsize, 0x68);
DAGU_ASSERT_OFF(usersize, 0x6c);
DAGU_ASSERT_OFF(compatsize, 0x70);
DAGU_ASSERT_OFF(hooks, 0x74);
DAGU_ASSERT_OFF(proto, 0x78);
DAGU_ASSERT_OFF(family, 0x7a);

_Static_assert(sizeof(struct dagu_xt_match) == 0x80, "xt_match size changed");
_Static_assert(__builtin_offsetof(struct dagu_xt_action_param, matchinfo) == 0x08,
	       "xt_action_param.matchinfo offset changed");
_Static_assert(__builtin_offsetof(struct dagu_xt_action_param, state) == 0x10,
	       "xt_action_param.state offset changed");
_Static_assert(__builtin_offsetof(struct dagu_nf_hook_state, in) == 0x08,
	       "nf_hook_state.in offset changed");
_Static_assert(__builtin_offsetof(struct dagu_nf_hook_state, out) == 0x10,
	       "nf_hook_state.out offset changed");
_Static_assert(__builtin_offsetof(struct dagu_nf_hook_state, net) == 0x20,
	       "nf_hook_state.net offset changed");
_Static_assert(sizeof(struct dagu_xt_addrtype_info) == 12,
	       "addrtype revision 0 matchsize changed");
_Static_assert(sizeof(struct dagu_xt_addrtype_info_v1) == 8,
	       "addrtype revision 1 matchsize changed");

/* ------------------------------------------------------------- accessors -- */

static void *dagu_xt_load_ptr(const void *base, unsigned int offset)
{
	return *(void *const volatile *)((const unsigned char *)base + offset);
}

static uint32_t dagu_xt_load_u32(const void *base, unsigned int offset)
{
	return *(const volatile uint32_t *)((const unsigned char *)base + offset);
}

static uint16_t dagu_xt_load_u16(const void *base, unsigned int offset)
{
	return *(const volatile uint16_t *)((const unsigned char *)base + offset);
}

static int dagu_xt_is_kernel_ptr(const void *p)
{
	return p && (unsigned long)p >= DAGU_KERNEL_ADDR_MIN;
}

/* --------------------------------------------------------------- matching -- */

/*
 * Resolve the IPv4 header the match inspects. A head pointer that is not a
 * kernel address means these offsets do not describe the running image, so the
 * caller is told there is nothing to match rather than dereferencing it.
 */
static const unsigned char *dagu_xt_ip_header(const void *skb)
{
	const unsigned char *head;
	unsigned int offset;

	if (!skb)
		return 0;

	head = (const unsigned char *)dagu_xt_load_ptr(skb, DAGU_SKB_HEAD);
	if (!dagu_xt_is_kernel_ptr(head))
		return 0;

	offset = dagu_xt_load_u16(skb, DAGU_SKB_NETWORK_HEADER);
	return head + offset;
}

typedef unsigned int (*dagu_inet_dev_addr_type_fn)(void *net, const void *dev,
						   uint32_t addr);

static dagu_inet_dev_addr_type_fn dagu_inet_dev_addr_type_ptr;

static int dagu_xt_match_type(void *net, const void *dev, uint32_t addr,
			      uint16_t mask)
{
	unsigned int type;

	if (mask == 0U)
		return 0;
	if (!dagu_xt_is_kernel_ptr(net))
		return 0;

	type = dagu_inet_dev_addr_type_ptr(net, dev, addr);
	/* inet_dev_addr_type returns an rtn_type; the mask holds one bit per
	 * type and a value past the mask width has no bit to test. */
	if (type >= 32U)
		return 0;
	return (mask & (uint16_t)(1U << type)) ? 1 : 0;
}

static int dagu_addrtype_match_v0(const void *skb, struct dagu_xt_action_param *par)
{
	const struct dagu_xt_addrtype_info *info;
	const unsigned char *iph;
	void *net;
	int ret = 1;

	if (!par || !par->state || !par->matchinfo)
		return 0;

	net = dagu_xt_load_ptr(par->state, __builtin_offsetof(struct dagu_nf_hook_state, net));
	info = (const struct dagu_xt_addrtype_info *)par->matchinfo;

	if (info->source == 0U && info->dest == 0U)
		return 1;

	iph = dagu_xt_ip_header(skb);
	if (!iph)
		return 0;
	/* NFPROTO_IPV4 records only reach this entry; confirm the header
	 * version before reading addresses out of it. */
	if ((iph[0] >> 4) != 4U)
		return 0;

	if (info->source != 0U) {
		int hit = dagu_xt_match_type(net, 0, dagu_xt_load_u32(iph, DAGU_IPH_SADDR),
					     info->source);
		ret = ret && (hit != (int)(info->invert_source & 1U));
	}
	if (ret && info->dest != 0U) {
		int hit = dagu_xt_match_type(net, 0, dagu_xt_load_u32(iph, DAGU_IPH_DADDR),
					     info->dest);
		ret = ret && (hit != (int)(info->invert_dest & 1U));
	}
	return ret;
}

static int dagu_addrtype_match_v1(const void *skb, struct dagu_xt_action_param *par)
{
	const struct dagu_xt_addrtype_info_v1 *info;
	const struct dagu_nf_hook_state *state;
	const unsigned char *iph;
	const void *dev = 0;
	int ret = 1;

	if (!par || !par->state || !par->matchinfo)
		return 0;

	state = par->state;
	info = (const struct dagu_xt_addrtype_info_v1 *)par->matchinfo;

	if (state->pf != DAGU_NFPROTO_IPV4)
		return 0;

	if (info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_IN)
		dev = state->in;
	else if (info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_OUT)
		dev = state->out;

	if (info->source == 0U && info->dest == 0U)
		return 1;

	iph = dagu_xt_ip_header(skb);
	if (!iph)
		return 0;
	if ((iph[0] >> 4) != 4U)
		return 0;

	if (info->source != 0U) {
		int hit = dagu_xt_match_type(state->net, dev,
					     dagu_xt_load_u32(iph, DAGU_IPH_SADDR),
					     info->source);
		ret = ret && (hit !=
			(int)((info->flags & DAGU_XT_ADDRTYPE_INVERT_SOURCE) != 0U));
	}
	if (ret && info->dest != 0U) {
		int hit = dagu_xt_match_type(state->net, dev,
					     dagu_xt_load_u32(iph, DAGU_IPH_DADDR),
					     info->dest);
		ret = ret && (hit !=
			(int)((info->flags & DAGU_XT_ADDRTYPE_INVERT_DEST) != 0U));
	}
	return ret;
}

static int dagu_addrtype_checkentry_v1(const struct dagu_xt_mtchk_param *par)
{
	const struct dagu_xt_addrtype_info_v1 *info;

	if (!par || !par->matchinfo)
		return -DAGU_EINVAL;

	info = (const struct dagu_xt_addrtype_info_v1 *)par->matchinfo;

	if ((info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_IN) &&
	    (info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_OUT))
		return -DAGU_EINVAL;

	if ((par->hook_mask & ((1U << DAGU_NF_INET_PRE_ROUTING) |
			       (1U << DAGU_NF_INET_LOCAL_IN))) &&
	    (info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_OUT))
		return -DAGU_EINVAL;

	if ((par->hook_mask & ((1U << DAGU_NF_INET_POST_ROUTING) |
			       (1U << DAGU_NF_INET_LOCAL_OUT))) &&
	    (info->flags & DAGU_XT_ADDRTYPE_LIMIT_IFACE_IN))
		return -DAGU_EINVAL;

	return 0;
}

/* ----------------------------------------------------------- registration -- */

typedef int (*dagu_xt_register_matches_fn)(struct dagu_xt_match *match,
					   unsigned int n);
typedef void (*dagu_xt_unregister_matches_fn)(struct dagu_xt_match *match,
					      unsigned int n);

static dagu_xt_register_matches_fn dagu_xt_register_matches_ptr;
static dagu_xt_unregister_matches_fn dagu_xt_unregister_matches_ptr;

/* Address of netfilter's "struct xt_af *xt". Reading it tells whether
 * xt_init() has allocated the per-family tables. */
static void *dagu_xt_table_ptr;

static struct dagu_xt_match dagu_addrtype_matches[] = {
	{
		.name = "addrtype",
		.revision = 0,
		.match = dagu_addrtype_match_v0,
		.matchsize = sizeof(struct dagu_xt_addrtype_info),
		.family = DAGU_NFPROTO_IPV4,
	},
	{
		.name = "addrtype",
		.revision = 1,
		.match = dagu_addrtype_match_v1,
		.checkentry = dagu_addrtype_checkentry_v1,
		.matchsize = sizeof(struct dagu_xt_addrtype_info_v1),
		.family = DAGU_NFPROTO_IPV4,
	},
};

/* 0 idle, 1 registration in progress, 2 registered */
static unsigned int dagu_xt_state;
static unsigned int dagu_xt_hooked;

static int dagu_xt_addrtype_register(void)
{
	int rc;

	/* xt_init() allocates the per-family tables. A null value means that
	 * callable has not run, and registering now would dereference it. */
	if (!dagu_xt_table_ptr || !dagu_xt_load_ptr(dagu_xt_table_ptr, 0))
		return -DAGU_EAGAIN;

	rc = dagu_xt_register_matches_ptr(dagu_addrtype_matches,
					  sizeof(dagu_addrtype_matches) /
						  sizeof(dagu_addrtype_matches[0]));
	if (rc) {
		logke("ds-dagu-xt: addrtype registration failed rc=%d\n", rc);
		return rc;
	}

	logki("ds-dagu-xt: registered addrtype match (ipv4, revisions 0 and 1)\n");
	return 0;
}

/*
 * Runs ahead of every match lookup. The first call is an iptables revision
 * probe or rule insertion; xt_init() has run by then, and the origin call made
 * right after this returns finds the match registered here.
 */
static void before_xt_find_match(hook_fargs3_t *args, void *udata)
{
	unsigned int expected = 0U;

	(void)args;
	(void)udata;

	if (__atomic_load_n(&dagu_xt_state, __ATOMIC_ACQUIRE) == 2U)
		return;
	if (!__atomic_compare_exchange_n(&dagu_xt_state, &expected, 1U, 0,
					 __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return;

	if (dagu_xt_addrtype_register() == 0)
		__atomic_store_n(&dagu_xt_state, 2U, __ATOMIC_RELEASE);
	else
		__atomic_store_n(&dagu_xt_state, 0U, __ATOMIC_RELEASE);
}

int dagu_xt_addrtype_install(void)
{
	void *target;
	int rc;

	if (dagu_xt_hooked)
		return -DAGU_EINVAL;

	dagu_xt_register_matches_ptr =
		(dagu_xt_register_matches_fn)kallsyms_lookup_name("xt_register_matches");
	dagu_xt_unregister_matches_ptr =
		(dagu_xt_unregister_matches_fn)kallsyms_lookup_name("xt_unregister_matches");
	dagu_inet_dev_addr_type_ptr =
		(dagu_inet_dev_addr_type_fn)kallsyms_lookup_name("inet_dev_addr_type");
	dagu_xt_table_ptr = (void *)kallsyms_lookup_name("xt");
	target = (void *)kallsyms_lookup_name("xt_find_match");

	if (!dagu_xt_register_matches_ptr || !dagu_xt_unregister_matches_ptr ||
	    !dagu_inet_dev_addr_type_ptr || !dagu_xt_table_ptr || !target) {
		logke("ds-dagu-xt: required symbols missing\n");
		return -2;
	}

	rc = hook_wrap3(target, before_xt_find_match, 0, 0);
	if (rc != HOOK_NO_ERR) {
		logke("ds-dagu-xt: xt_find_match hook failed rc=%d\n", rc);
		return -(int)rc;
	}

	dagu_xt_hooked = 1U;
	logki("ds-dagu-xt: armed; registration deferred to first match lookup\n");
	return 0;
}

void dagu_xt_addrtype_uninstall(void)
{
	void *target;

	if (!dagu_xt_hooked)
		return;

	target = (void *)kallsyms_lookup_name("xt_find_match");
	if (target)
		unhook(target);

	if (__atomic_load_n(&dagu_xt_state, __ATOMIC_ACQUIRE) == 2U)
		dagu_xt_unregister_matches_ptr(dagu_addrtype_matches,
					       sizeof(dagu_addrtype_matches) /
						       sizeof(dagu_addrtype_matches[0]));

	dagu_xt_state = 0U;
	dagu_xt_hooked = 0U;
}
