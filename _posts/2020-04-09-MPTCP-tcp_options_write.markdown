---
layout: default
title:  "tcp_options_write hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_output.c */
/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operability perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			      struct tcp_out_options *opts, struct sk_buff *skb)
{
	u16 options = opts->options;	/* mungable copy */

	/* TCPOPT_MD5SIG=19 MD5 Signature option RFC2385 */
	if (unlikely(OPTION_MD5 & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}

	/* TCPOLEN_MSS=2 Maximum Segment Size option RFC793 */
	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	/* TCPOPT_TIMESTAMP=8 Timestamps option RFC7323*/
	/* TCPOPT_SACK_PERM=4 SACK Permitted option RFC2018 */
	/* 由于网络对字节顺序敏感，这两个option要一起考虑 */
	if (likely(OPTION_TS & options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

	/* TCPOPT_SACK_PERM=4 SACK Permitted option RFC2018 */
	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}

	/* TCPOPT_WINDOW=3 Window Scale option RFC7323 */
	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}

	/* TCPOPT_SACK=5 SACK option RFC2018 */
	if (unlikely(opts->num_sack_blocks)) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

		tp->rx_opt.dsack = 0;
	}

	/* Fast open信息交换有两种方式，一种是根据IANA安排，使用TCP Fast Open 
	Cookie option kind=34(RFC7413)，另一种方式是使用experimental 
	option(kind=254 rfc6994)。使用哪一种由之前cached cookie所存储的决定，
	参考tcp_connect->tcp_send_syn_data流程 */
	if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
		struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;
		u8 *p = (u8 *)ptr;
		u32 len; /* Fast Open option length */
		/* exp成员表示使用何种方式(kind 34还是kind 254)进行fast open信息交换 */
		if (foc->exp) {
			len = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
			/* TCPOPT_EXP=254 experiment方式*/
			*ptr = htonl((TCPOPT_EXP << 24) | (len << 16) |
				     TCPOPT_FASTOPEN_MAGIC);
			p += TCPOLEN_EXP_FASTOPEN_BASE;
		} else {
			/* TCPOPT_FASTOPEN=34 RFC7413 方式 */
			len = TCPOLEN_FASTOPEN_BASE + foc->len;
			*p++ = TCPOPT_FASTOPEN;
			*p++ = len;
		}

		memcpy(p, foc->val, foc->len);
		if ((len & 3) == 2) {
			p[foc->len] = TCPOPT_NOP;
			p[foc->len + 1] = TCPOPT_NOP;
		}
		ptr += (len + 3) >> 2;
	}

	/* 利用TCP experimental option配置SMC-R协议 */
	/* SMC - Shared Memory Communication. SMC-R(SMC over RDMA)协议(参考RFC7609)
	使用的是TCP experimental option(对应kind是253/254，关于TCP experimental 
	option参考rfc6994) 此函数会生成真正的TCP experimental option报文，和smc_set_option
	的作用注意区分*/
	smc_options_write(ptr, &options);

	/* 生成MPTCP option报文，详情点击下方链接*/
	if (unlikely(OPTION_MPTCP & opts->options))
		mptcp_options_write(ptr, tp, opts, skb);
}
```

[mptcp_options_write](MPTCP-mptcp_options_write.html)

返回 [tcp_transmit_skb](MPTCP-tcp_transmit_skb.html)