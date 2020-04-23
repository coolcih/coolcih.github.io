---
layout: post
title:  "MPTCP代码分析 - MPTCP能力协商，TCP SYN的发送流程"
date:   2020-04-09 12:06:58 +0800
categories: Network technology
---




```c
/* net/ipv4/tcp_ipv4.c */
//用户空间调用connect函数后，会触发此函数调用。此函数会最后触发TCP SYN包发出。
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	...//TODO添加必要函数注释
        
	/*TODO*/
	rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
			      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			      IPPROTO_TCP,
			      orig_sport, orig_dport, sk);

	...//TODO添加必要函数注释
        
	/* Build a SYN and send it off. */
	err = tcp_connect(sk);
}
```

[ip_route_connect](MPTCP-ip_route_connect.html)

[tcp_connect](MPTCP-tcp_connect.html)

<a href="{{ "/" | relative_url }}">{{ "返回主页" | escape }}</a>