---
layout: default
title:  "tcp_syn_options hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_output.c */
/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;
	struct tcp_fastopen_request *fastopen = tp->fastopen_req;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (unlikely(rcu_access_pointer(tp->md5sig_info))) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			remaining -= TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

    /* 计算TCP timestamp option */
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
    
    /* 计算TCP window scale option */
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
    
    /* 计算TCP SACK option */
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
    
    /* 计算TCP MPTCP option */
	if (tp->request_mptcp || mptcp(tp))
		mptcp_syn_options(sk, opts, &remaining);/* 详情点击下方链接 */

    /* 计算TCP fastopen option */
	if (fastopen && fastopen->cookie.len >= 0) {
		u32 need = fastopen->cookie.len;

		need += fastopen->cookie.exp ? TCPOLEN_EXP_FASTOPEN_BASE :
					       TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = &fastopen->cookie;
			remaining -= need;
			tp->syn_fastopen = 1;
			tp->syn_fastopen_exp = fastopen->cookie.exp ? 1 : 0;
		}
	}
	/* 利用TCP experimental option配置SMC-R协议 */
	/* SMC - Shared Memory Communication. SMC-R(SMC over RDMA)协议(参考RFC7609)
	使用的是TCP experimental option(对应kind是253/254，关于TCP experimental 
	option参考rfc6994) 此函数不会生成TCP experimental option报文，它只只负责设置相关
	的flag，报文生成由smc_options_write函数负责。*/
	smc_set_option(tp, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}
```

[mptcp_syn_options](MPTCP-mptcp_syn_options.html)

返回 [tcp_transmit_skb](MPTCP-tcp_transmit_skb.html)