/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

#ifndef __KERNEL__
#warning This file is not supposed to be used outside of kernel.
#endif

#define RTO_ONLINK	0x01

#define RTO_CONN	0
/* RTO_CONN is not used (being alias for 0), but preserved not to break
 * some modules referring to it. */

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct inet_peer;

/*
 The routing table, rtable, defined in file linux/include/net/route.h, is the fundamental data
 structure that holds each route in the route cache. Like many data structures in the Linux
 implementation of IPv4, it is essentially object oriented. This is how the routing cache can be
 considered to be derived from the generic destination cache facility. For example, the socket
 buffer structure, sk_buff, contains a pointer to the destination cache entry for an outgoing packet.
 This entry, dst, can contain a pointer to the routing cache entry for the packet. Therefore, the
 rtable structure is defined in such a way that the first few fields are identical to the fields of the
 destination cache, dst_entry.
 */
struct rtable
{
	union
	{
		struct dst_entry	dst;
	} u;

	/* Cache lookup keys */
	/* fl, contains the actual hash key. */
	struct flowi		fl;

	struct in_device	*idev;

	/*
     The rt_flags field contains the routing table flags, which are also used by the application
     interface to the routing table.
     */	
	unsigned		rt_flags;
	/*
	 rt_type is the type of this route. For example, it specifies whether the route is unicast, 
	 multicast, or a local route. 
     */
	__u16			rt_type;

	/*
     rt_dst is the IP destination address, rt_src is the IP source address, 
     */
	__be32			rt_dst;	/* Path destination	*/
	__be32			rt_src;	/* Path source		*/
	/*
	 rt_iif is the route input interface index.
     */
	int			rt_iif;

	/* Info on neighbour */
	/* The IP address of the gateway machine or neighbor is in the field rt_gateway. */
	__be32			rt_gateway;

	/* Miscellaneous cached information */
	/*
     rt_spec_dst, is the specific destination for the use of UDP socket users to set the source address.  
     */
	__be32			rt_spec_dst; /* RFC1122 specific destination */
	/*
     Internet peer structures are used for generating the 16-bit 
	 identification in the IP header. This is called the long-living peer information. 
     Linux calculates the ID by incrementing a number for
     each transmitted packet for a specific host. 
     */
	struct inet_peer	*peer; /* long-living peer info */
};

struct ip_rt_acct
{
	__u32 	o_bytes;
	__u32 	o_packets;
	__u32 	i_bytes;
	__u32 	i_packets;
};

struct rt_cache_stat 
{
        unsigned int in_hit;
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
        unsigned int in_no_route;
        unsigned int in_brd;
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
        unsigned int out_hit;
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
        unsigned int gc_total;
        unsigned int gc_ignored;
        unsigned int gc_goal_miss;
        unsigned int gc_dst_overflow;
        unsigned int in_hlist_search;
        unsigned int out_hlist_search;
};

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(__be32 old_gw, __be32 dst, __be32 new_gw,
				       __be32 src, struct net_device *dev);
extern void		rt_cache_flush(int how);
extern int		__ip_route_output_key(struct rtable **, const struct flowi *flp);
extern int		ip_route_output_key(struct rtable **, struct flowi *flp);
extern int		ip_route_output_flow(struct rtable **rp, struct flowi *flp, struct sock *sk, int flags);
extern int		ip_route_input(struct sk_buff*, __be32 dst, __be32 src, u8 tos, struct net_device *devin);
extern unsigned short	ip_rt_frag_needed(struct iphdr *iph, unsigned short new_mtu);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(__be32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

struct in_ifaddr;
extern void fib_add_ifaddr(struct in_ifaddr *);

static inline void ip_rt_put(struct rtable * rt)
{
	if (rt)
		dst_release(&rt->u.dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern const __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

/*
 main function for resolving routes for output packets.
 */
static inline int ip_route_connect(struct rtable **rp, __be32 dst,
				   __be32 src, u32 tos, int oif, u8 protocol,
				   __be16 sport, __be16 dport, struct sock *sk,
				   int flags)
{
	struct flowi fl = { .oif = oif,
			    .nl_u = { .ip4_u = { .daddr = dst,
						 .saddr = src,
						 .tos   = tos } },
			    .proto = protocol,
			    .uli_u = { .ports =
				       { .sport = sport,
					 .dport = dport } } };

	int err;
	
	/*
     we try to update both the source and destination addresses if one is missing.
     */
	if (!dst || !src) {
		err = __ip_route_output_key(rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	security_sk_classify_flow(sk, &fl);

	/*
     If both the source and destination addresses are defined, we pass in a pointer to the sock in sk.
	 The function ip_route_output_flow can automatically transform the route if the protocol value in
     the flowi structure is set to NAT or some other nonzero number.
     */
	return ip_route_output_flow(rp, &fl, sk, flags);
}

static inline int ip_route_newports(struct rtable **rp, u8 protocol,
				    __be16 sport, __be16 dport, struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));
		fl.fl_ip_sport = sport;
		fl.fl_ip_dport = dport;
		fl.proto = protocol;
		ip_rt_put(*rp);
		*rp = NULL;
		security_sk_classify_flow(sk, &fl);
		return ip_route_output_flow(rp, &fl, sk, 0);
	}
	return 0;
}

extern void rt_bind_peer(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	rt_bind_peer(rt, 0);
	return rt->peer;
}

extern ctl_table ipv4_route_table[];

#endif	/* _ROUTE_H */
