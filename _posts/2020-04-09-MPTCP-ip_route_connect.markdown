---
layout: default
title:  "ip_route_connect hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* include/net/route.h */
static inline struct rtable *ip_route_connect(struct flowi4 *fl4,
					      __be32 dst, __be32 src, u32 tos,
					      int oif, u8 protocol,
					      __be16 sport, __be16 dport,
					      struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct rtable *rt;

	ip_route_connect_init(fl4, dst, src, tos, oif, protocol,
			      sport, dport, sk);

	if (!dst || !src) {
		rt = __ip_route_output_key(net, fl4);
		if (IS_ERR(rt))
			return rt;
		ip_rt_put(rt);
		flowi4_update_output(fl4, oif, tos, fl4->daddr, fl4->saddr);
	}
	security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
	return ip_route_output_flow(net, fl4, sk);
}
```

[dummy](MPTCP-<functionname>.html)