---
layout: default
title:  "tcp_v4_init_sock hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_ipv4.c */
/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
/* 初始化sock，包括 inet_connection_sock(address family相关)，
                    tcp_sock(address family无关) */
static int tcp_v4_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	/* tcp中和address family无关的部分，由此函数负责初始化。
	如何理解"address family无关"? tcp是传输层协议，它的下层是
	网络层也就是IP层，而IP又分IPv4和IPv6，因为是相邻两层，传输
	数据时肯定得交互，所以TCP必须根据不同的IP协议分别处理，这种
	依赖于具体IP协议的处理就是"address family相关"，有相关也就
	有无关的，协议分层的目的就是减少相关性，所以TCP的很多操作和IP层
	是无关的这就是所谓的"address family无关"。kernel代码实现时，
	就是把和"address family无关"相关初始化放到这个函数进行。而和
	"address family相关"的放在tcp_v4_init_sock中，下面可以看到
	icsk->icsk_af_ops会根据使用的协议类型设置对应的操作。 可以
	进一步对比tcp_ipv6::tcp_v6_init_sock，也会调用tcp_init_soc
	对tcp sock进行"address family无关"的初始化，然后在tcp_v6_init_sock
	中将icsk->icsk_af_ops设成mptcp_v6_specific或ipv6_specific */
	tcp_init_sock(sk);/* 详见下 */

#ifdef CONFIG_MPTCP
	if (sock_flag(sk, SOCK_MPTCP))
		/* 将inet_connection_sock的操作设置为MPTCP相关的 */
		icsk->icsk_af_ops = &mptcp_v4_specific;
	else
#endif
		/* 将inet_connection_sock的操作设置为IPv4相关的 */
		icsk->icsk_af_ops = &ipv4_specific;

#ifdef CONFIG_TCP_MD5SIG
	tcp_sk(sk)->af_specific = &tcp_sock_ipv4_specific;
#endif

	return 0;
}
```

```c
/* net/mptcp/mptcp_ipv4.c */
const struct inet_connection_sock_af_ops mptcp_v4_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = inet_sk_rx_dst_set,
	.conn_request	   = mptcp_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};

/* net/ipv4/tcp_ipv4.c */
const struct inet_connection_sock_af_ops ipv4_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = inet_sk_rx_dst_set,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};
```



```c
/* net/ipv4/tcp.c */
/* Address-family independent initialization for a tcp_sock.
 *
 * NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
void tcp_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	tp->out_of_order_queue = RB_ROOT;
	sk->tcp_rtx_queue = RB_ROOT;
	tcp_init_xmit_timers(sk);
	INIT_LIST_HEAD(&tp->tsq_node);
	INIT_LIST_HEAD(&tp->tsorted_sent_queue);

	icsk->icsk_rto = TCP_TIMEOUT_INIT;
	tp->mdev_us = jiffies_to_usecs(TCP_TIMEOUT_INIT);
	minmax_reset(&tp->rtt_min, tcp_jiffies32, ~0U);

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = TCP_INIT_CWND;

	/* There's a bubble in the pipe until at least the first ACK. */
	tp->app_limited = ~0U;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	tp->reordering = sock_net(sk)->ipv4.sysctl_tcp_reordering;
	tcp_assign_congestion_control(sk);

	tp->tsoffset = 0;
	tp->rack.reo_wnd_steps = 1;

	sk->sk_state = TCP_CLOSE;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_sync_mss = tcp_sync_mss;

	sk->sk_sndbuf = sock_net(sk)->ipv4.sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sock_net(sk)->ipv4.sysctl_tcp_rmem[1];

	tp->ops = &tcp_specific;

	/* Initialize MPTCP-specific stuff and function-pointers */
	mptcp_init_tcp_sock(sk);/* 详见下 */

	sk_sockets_allocated_inc(sk);
	sk->sk_route_forced_caps = NETIF_F_GSO;
}
```



```c
/* include/net/mptcp.h */
/* Initializes function-pointers and MPTCP-flags */
static inline void mptcp_init_tcp_sock(struct sock *sk)
{
	/* MPTCP_SYSCT=1，只有在sysctl_mptcp_enabled为1时才会给所有sock都加上MPTCP能力
	MPTCP有3中使用方式：
	sysctl_mptcp_enabled=0，关闭MPTCP。
	sysctl_mptcp_enabled=1，默认为所有TCP连接都使用MPTCP。
	sysctl_mptcp_enabled=2，上层应用(用户空间)，请求使用MPTCP时才使用MPTCP，应用在
	                       创建sokcet时自己设上SOCK_MPTCP标志。 */
	if (!mptcp_init_failed && sysctl_mptcp_enabled == MPTCP_SYSCTL)
		mptcp_enable_sock(sk);/* 此函数把所有sock都加上了MPTCP能力，详见下 */
}
```



```c
/* net/mptcp/mptcp_ctrl.c */
void mptcp_enable_sock(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_MPTCP)) {/* 如果sock没有设置SOCK_MPTCP，就都设。 */
		sock_set_flag(sk, SOCK_MPTCP);
		tcp_sk(sk)->mptcp_ver = sysctl_mptcp_version;

		/* Necessary here, because MPTCP can be enabled/disabled through
		 * a setsockopt.
		 */
		if (sk->sk_family == AF_INET)
			inet_csk(sk)->icsk_af_ops = &mptcp_v4_specific;
#if IS_ENABLED(CONFIG_IPV6)
		else if (mptcp_v6_is_v4_mapped(sk))
			inet_csk(sk)->icsk_af_ops = &mptcp_v6_mapped;
		else
			inet_csk(sk)->icsk_af_ops = &mptcp_v6_specific;
#endif

		mptcp_enable_static_key();
	}
}
```

返回 [tcp_transmit_skb](MPTCP-tcp_transmit_skb.html) /* TODO */

