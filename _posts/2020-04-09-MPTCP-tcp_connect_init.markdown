---
layout: default
title:  "tcp_connect_init hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_output.c */
/* Do all connect socket setups that can be done AF independent. */
/* 在Unix/Linux系统中，在不同的版本中AF_INET和PF_INET有微小差别.对于BSD,是AF,
   对于POSIX是PF。AF = Address Family /  PF = Protocol Family
   理论上建立socket时是指定协议，应该用PF_xxxx，设置地址时应该用AF_xxxx。当然AF_INET
   和PF_INET的值是相同的，混用也不会有太大的问题。在函数socketpair与socket的domain参
   数中有AF_UNIX,AF_LOCAL,AF_INET,PF_UNIX,PF_LOCAL,PF_INET。这几个参数有
   AF_UNIX=AF_LOCAL, PF_UNIX=PF_LOCAL, AF_LOCAL=PF_LOCAL, AF_INET=PF_INET。
   建议:对于socketpair与socket的domain参数,使用PF_LOCAL系列,而在初始化套接口地址结
   构时,则使用AF_LOCAL. 例如:
   z = socket(PF_LOCAL, SOCK_STREAM, 0);
   adr_unix.sin_family = AF_LOCAL; */
/* 此函数设置TCP初始的MTU，拥塞控制算法(ca - congestion algrithm)，最大的广播窗口，
   自己的MSS，猜测对端的MSS，自己的接收窗口大小，基本上不依赖它处就可以初始化的参数都在
   这个函数做。对于MPTCP，不依赖于它处的参数也在这个函数中进行初始化，参数初始化时分两种
   情况，1. 主sock，也就是meta sock。2. 新subflow对应的sock。*/
static void tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);/* dst就是目的地，存的是路由信息 */
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;
	u32 rcv_wnd;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr);
	if (sock_net(sk)->ipv4.sysctl_tcp_timestamps)
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss; /* Maximal mss, negotiated at
                                                            connection setup。这里只是把
                                                            用户设置的mss设置进来，最终的值
                                                            还需协商 */
	tp->max_window = 0;
	tcp_mtup_init(sk); /* 设置mtu */
	tcp_sync_mss(sk, dst_mtu(dst));

	tcp_ca_dst_init(sk, dst); /* 拥塞算法 */

	if (!tp->window_clamp) /* window_clamp是Maximal window to advertise */
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));/* advmss是Advertised MSS */

	tcp_initialize_rcv_mss(sk);/* 猜测对端的mss，存于inet_csk(sk)->icsk_ack.rcv_mss中 */
	/* struct sock是基本结构，struct inet_sock是struct sock的扩展，所谓扩展就是inet_sock结构
	   的第一个成员是一个struct sock，然后再其后填加新成员，而inet_connection_sock又是
	   inet_sock的扩展。inet_csk(sk)是将传入的sk(struct sock)强制类型转换成
	   inet_connection_sock，因为有前述的扩展关系，才可以这样做。 */

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

	rcv_wnd = tcp_rwnd_init_bpf(sk);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);

	tp->ops->select_initial_window(sk, tcp_full_space(sk),
				       tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				       &tp->rcv_wnd,
				       &tp->window_clamp,
				       sock_net(sk)->ipv4.sysctl_tcp_window_scaling,
				       &rcv_wscale,
				       rcv_wnd);/* 设置接收窗口 */

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0; /* 发送窗口初始化为0 */
	tcp_init_wl(tp, 0);
	tcp_write_queue_purge(sk);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->snd_nxt = tp->write_seq;

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	else
		tp->rcv_tstamp = tcp_jiffies32;
	tp->rcv_wup = tp->rcv_nxt;
	tp->copied_seq = tp->rcv_nxt;

	inet_csk(sk)->icsk_rto = tcp_timeout_init(sk);
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);

#ifdef CONFIG_MPTCP
	if (sock_flag(sk, SOCK_MPTCP) && mptcp_doit(sk)) {
		if (is_master_tp(tp)) { /* 条件成立，是主sock - meta sock */
			tp->request_mptcp = 1; /* 为1才会在SYN中带MP_CAPABLE */
			mptcp_connect_init(sk); /* 进行mptcp的参数初始化，详情点击下方链接*/
		} else if (tp->mptcp) {/* 条件成立，是新subflow的sock */
			struct inet_sock *inet	= inet_sk(sk);/* inet_sock是sock的扩展，所以可
			                                         将sk强制类型转换为inet_sock */

			tp->mptcp->snt_isn	= tp->write_seq;/* 设置mptcp的initial seq number */
			tp->mptcp->init_rcv_wnd	= tp->rcv_wnd;/* mptcp的接收窗口 */ 

			/* Set nonce for new subflows */
			if (sk->sk_family == AF_INET)
				tp->mptcp->mptcp_loc_nonce = mptcp_v4_get_nonce(
							inet->inet_saddr,
							inet->inet_daddr,
							inet->inet_sport,
							inet->inet_dport);/* 计算本端的nonce，
							                     nonce用途参考
							                     rfc6824 2.2节。*/
#if IS_ENABLED(CONFIG_IPV6)
			else
				tp->mptcp->mptcp_loc_nonce = mptcp_v6_get_nonce(
						inet6_sk(sk)->saddr.s6_addr32,
						sk->sk_v6_daddr.s6_addr32,
						inet->inet_sport,
						inet->inet_dport);
#endif
		}
	}
#endif
}
```

[mptcp_connect_init](MPTCP-mptcp_connect_init.html)

返回 [tcp_connect](MPTCP-tcp_connect.html)

