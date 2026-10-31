/*
 * Minimal macvlan link type: one lower device, bridge-style delivery.
 *
 * The vendor kernel ships no macvlan support and its own drivers/net/macvlan.c
 * faults during device registration, so this module implements the rtnl link
 * type itself. Frames received on the lower device are handed to the macvlan
 * device whose address matches, and transmitted frames are queued on the lower
 * device.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <net/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_macvlan.h>
#include <linux/slab.h>
#include <linux/list.h>

struct dagu_mv {
	struct net_device *dev;
	struct net_device *lower;
	struct list_head list;		/* on port->head */
	struct dagu_mv_port *port;
};

struct dagu_mv_port {
	struct list_head node;		/* on dagu_mv_ports */
	struct list_head head;		/* of dagu_mv */
	struct net_device *lower;
};

static LIST_HEAD(dagu_mv_ports);
static DEFINE_MUTEX(dagu_mv_lock);

static struct dagu_mv_port *dagu_mv_port_find(struct net_device *lower)
{
	struct dagu_mv_port *p;

	list_for_each_entry(p, &dagu_mv_ports, node)
		if (p->lower == lower)
			return p;
	return NULL;
}

static rx_handler_result_t dagu_mv_handle(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct net_device *lower = skb->dev;
	struct dagu_mv_port *p = rcu_dereference(lower->rx_handler_data);
	const unsigned char *dst = eth_hdr(skb)->h_dest;
	bool bcast = is_broadcast_ether_addr(dst);
	bool mcast = is_multicast_ether_addr(dst);
	struct dagu_mv *mv;

	if (unlikely(!p))
		return RX_HANDLER_PASS;

	list_for_each_entry_rcu(mv, &p->head, list) {
		if (!(mv->dev->flags & IFF_UP))
			continue;
		if (!bcast && !mcast && !ether_addr_equal(dst, mv->dev->dev_addr))
			continue;
		if (skb_shared(skb)) {
			struct sk_buff *n = skb_clone(skb, GFP_ATOMIC);

			if (!n)
				return RX_HANDLER_PASS;
			n->dev = mv->dev;
			n->pkt_type = PACKET_HOST;
			netif_rx(n);
			continue;
		}
		skb->dev = mv->dev;
		skb->pkt_type = PACKET_HOST;
		netif_rx(skb);
		return RX_HANDLER_CONSUMED;
	}
	return RX_HANDLER_PASS;
}

static netdev_tx_t dagu_mv_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dagu_mv *mv = netdev_priv(dev);

	skb->dev = mv->lower;
	skb->priority = 0;
	dev_queue_xmit(skb);
	return NETDEV_TX_OK;
}

static int dagu_mv_open(struct net_device *dev)
{
	struct dagu_mv *mv = netdev_priv(dev);

	dev_uc_add(mv->lower, dev->dev_addr);
	netif_carrier_on(dev);
	return 0;
}

static int dagu_mv_stop(struct net_device *dev)
{
	struct dagu_mv *mv = netdev_priv(dev);

	dev_uc_del(mv->lower, dev->dev_addr);
	netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops dagu_mv_netdev_ops = {
	.ndo_open		= dagu_mv_open,
	.ndo_stop		= dagu_mv_stop,
	.ndo_start_xmit		= dagu_mv_xmit,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
};

static void dagu_mv_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_UNICAST_FLT;
	dev->netdev_ops = &dagu_mv_netdev_ops;
	dev->needs_free_netdev = true;
	dev->min_mtu = 0;
	dev->max_mtu = ETH_MAX_MTU;
}

static void dagu_mv_put(struct dagu_mv *mv)
{
	struct dagu_mv_port *p = mv->port;

	list_del_rcu(&mv->list);
	dev_put(mv->lower);
	if (list_empty(&p->head)) {
		netdev_rx_handler_unregister(p->lower);
		list_del(&p->node);
		kfree(p);
	}
}

static int dagu_mv_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[],
			   struct netlink_ext_ack *extack)
{
	struct dagu_mv *mv = netdev_priv(dev);
	struct net_device *lower;
	struct dagu_mv_port *p;
	int err;

	if (!tb[IFLA_LINK])
		return -EINVAL;
	lower = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (!lower)
		return -ENODEV;
	if (lower->type != ARPHRD_ETHER || (lower->flags & IFF_LOOPBACK))
		return -EINVAL;

	if (tb[IFLA_ADDRESS] && nla_len(tb[IFLA_ADDRESS]) >= ETH_ALEN) {
		memcpy(dev->dev_addr, nla_data(tb[IFLA_ADDRESS]), ETH_ALEN);
		if (!is_valid_ether_addr(dev->dev_addr))
			return -EADDRNOTAVAIL;
	} else {
		eth_hw_addr_random(dev);
	}

	mv->dev = dev;
	mv->lower = lower;
	dev_hold(lower);

	mutex_lock(&dagu_mv_lock);
	p = dagu_mv_port_find(lower);
	if (!p) {
		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p) {
			mutex_unlock(&dagu_mv_lock);
			dev_put(lower);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&p->head);
		p->lower = lower;
		err = netdev_rx_handler_register(lower, dagu_mv_handle, p);
		if (err) {
			kfree(p);
			mutex_unlock(&dagu_mv_lock);
			dev_put(lower);
			return err;
		}
		list_add_tail(&p->node, &dagu_mv_ports);
	}
	mv->port = p;
	list_add_tail_rcu(&mv->list, &p->head);
	mutex_unlock(&dagu_mv_lock);

	err = register_netdevice(dev);
	if (err)
		goto fail;

	dev->priv_flags |= IFF_MACVLAN;
	err = netdev_upper_dev_link(lower, dev, extack);
	if (err)
		goto fail_unreg;

	netif_stacked_transfer_operstate(lower, dev);
	return 0;

fail_unreg:
	unregister_netdevice(dev);
fail:
	mutex_lock(&dagu_mv_lock);
	dagu_mv_put(mv);
	mutex_unlock(&dagu_mv_lock);
	return err;
}

static void dagu_mv_dellink(struct net_device *dev, struct list_head *head)
{
	struct dagu_mv *mv = netdev_priv(dev);

	netdev_upper_dev_unlink(mv->lower, dev);
	unregister_netdevice_queue(dev, head);
	mutex_lock(&dagu_mv_lock);
	dagu_mv_put(mv);
	mutex_unlock(&dagu_mv_lock);
}

static const struct nla_policy dagu_mv_policy[IFLA_MACVLAN_MAX + 1] = {
	[IFLA_MACVLAN_MODE] = { .type = NLA_U32 },
	[IFLA_MACVLAN_FLAGS] = { .type = NLA_U16 },
};

static struct rtnl_link_ops dagu_mv_link_ops __read_mostly = {
	.kind = "macvlan",
	.priv_size = sizeof(struct dagu_mv),
	.setup = dagu_mv_setup,
	.newlink = dagu_mv_newlink,
	.dellink = dagu_mv_dellink,
	.maxtype = IFLA_MACVLAN_MAX,
	.policy = dagu_mv_policy,
};

static int __init dagu_mv_init(void)
{
	int err = rtnl_link_register(&dagu_mv_link_ops);

	pr_info("dagu-macvlan: register rc=%d\n", err);
	return err;
}

static void __exit dagu_mv_exit(void)
{
	rtnl_link_unregister(&dagu_mv_link_ops);
	pr_info("dagu-macvlan: unregistered\n");
}

module_init(dagu_mv_init);
module_exit(dagu_mv_exit);
MODULE_LICENSE("GPL");
