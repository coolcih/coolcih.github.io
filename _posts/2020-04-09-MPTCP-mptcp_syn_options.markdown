---
layout: default
title:  "mptcp_syn_options hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/mptcp/mptcp_output.c */
void mptcp_syn_options(const struct sock *sk, struct tcp_out_options *opts,
		       unsigned *remaining)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* mptcp.h定义OPTION_MPTCP值是(1 << 5)，注意opts->options的值并不是
	TCP MPTCP option kind(值30)，opts->options只是代码内部使用的flag，用
	来告诉后续调用函数tcp_options_write->mptcp_options_write需要生成真正
	的MPTCP option。 */
	opts->options |= OPTION_MPTCP;
	if (is_master_tp(tp)) {//主sock
        /* MP_CAPABLE是在TCP SYN携带的所以OPTION_MP_CAPABLE | OPTION_TYPE_SYN */
		opts->mptcp_options |= OPTION_MP_CAPABLE | OPTION_TYPE_SYN;
		opts->mptcp_ver = tcp_sk(sk)->mptcp_ver;
		*remaining -= MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN;
 		/* local key已经在mptcp_connect_init调用中生成了 */
		opts->mp_capable.sender_key = tp->mptcp_loc_key;
		/* 设置是否协商需要校验，这个对应MP_CAPABLE中的A flag，参考rfc6824 3.1节 */
		opts->dss_csum = !!sysctl_mptcp_checksum;
	} else {//subflow sock，对应新增一个subflow的情况，对应MP_JOIN
		const struct mptcp_cb *mpcb = tp->mpcb;
		/* MP_JOIN是在TCP SYN携带的所以OPTION_MP_JOIN | OPTION_TYPE_SYN */
		opts->mptcp_options |= OPTION_MP_JOIN | OPTION_TYPE_SYN;
		*remaining -= MPTCP_SUB_LEN_JOIN_SYN_ALIGN;
		/* MP_JOIN需要携带receiver token，参考rfc6824 3.2节*/
		opts->mp_join_syns.token = mpcb->mptcp_rem_token;
		opts->mp_join_syns.low_prio  = tp->mptcp->low_prio;
		/* MP_JOIN的address id项，参考rfc6824 3.2节 */
		opts->addr_id = tp->mptcp->loc_id;
		/* MP_JOIN的sender random number */
		opts->mp_join_syns.sender_nonce = tp->mptcp->mptcp_loc_nonce;
	}
}
```

返回 [tcp_syn_options](MPTCP-tcp_syn_options.html)