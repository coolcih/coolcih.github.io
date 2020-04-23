---
layout: default
title:  "mptcp_options_write hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/mptcp/mptcp_output.c */
/* mptcp_syn_options负责设置相关flag, opts->mptcp_options
   mptcp_options_write根据opts->mptcp_options负责生成MPTCP报文*/
void mptcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			 const struct tcp_out_options *opts,
			 struct sk_buff *skb)
{
	/* MPTCP option携带MP_CAPABLE的情况，两端协商MPTCP能力，rfc6824 3.1节 */
	if (unlikely(OPTION_MP_CAPABLE & opts->mptcp_options)) {
		struct mp_capable *mpc = (struct mp_capable *)ptr;
		/* RFC6824 TCPOPT_MPTCP=30 TCP MPTCP option kind是30 */
		mpc->kind = TCPOPT_MPTCP;
		/* TCP三次握手(SYN, SYNACK, ACK)都要携带MP_CAPABLE，相当于MPTCP的三次握手*/
		if ((OPTION_TYPE_SYN & opts->mptcp_options) ||
		    (OPTION_TYPE_SYNACK & opts->mptcp_options)) {
			mpc->sender_key = opts->mp_capable.sender_key;
			mpc->len = MPTCP_SUB_LEN_CAPABLE_SYN;
			mpc->ver = opts->mptcp_ver;
			ptr += MPTCP_SUB_LEN_CAPABLE_SYN_ALIGN >> 2;
		} else if (OPTION_TYPE_ACK & opts->mptcp_options) {
			mpc->sender_key = opts->mp_capable.sender_key;
			mpc->receiver_key = opts->mp_capable.receiver_key;
			mpc->len = MPTCP_SUB_LEN_CAPABLE_ACK;
			mpc->ver = opts->mptcp_ver;
			ptr += MPTCP_SUB_LEN_CAPABLE_ACK_ALIGN >> 2;
		}
		/* subtype MPTCP_SUB_CAPABLE=0表示MP_CAPABLE rfc6824 3.1节 */
		mpc->sub = MPTCP_SUB_CAPABLE;
		mpc->a = opts->dss_csum;/* MP_CAPABLE A flag，是否需要校验 */
		mpc->b = 0;/* MP_CAPABLE B flag，扩展位，必须为0 */
		mpc->rsv = 0; /* C-H flag，加密算法协商，目前只H置位 */
		mpc->h = 1;/* H位表示使用HMAC-SHA1算法 */
	}
	/* 携带MP_JOIN情况，添加新的subflow，rfc6824 3.2节 */
	if (unlikely(OPTION_MP_JOIN & opts->mptcp_options)) {
		struct mp_join *mpj = (struct mp_join *)ptr;

		mpj->kind = TCPOPT_MPTCP;/* kind=30 */
		/* subtype MPTCP_SUB_JOIN=1表示MP_JOIN rfc6824 3.2节 */
		mpj->sub = MPTCP_SUB_JOIN;
		mpj->rsv = 0;

		if (OPTION_TYPE_SYN & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_SYN;
			mpj->u.syn.token = opts->mp_join_syns.token;
			mpj->u.syn.nonce = opts->mp_join_syns.sender_nonce;
			mpj->b = opts->mp_join_syns.low_prio;
			mpj->addr_id = opts->addr_id;
			ptr += MPTCP_SUB_LEN_JOIN_SYN_ALIGN >> 2;
		} else if (OPTION_TYPE_SYNACK & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_SYNACK;
			mpj->u.synack.mac =
				opts->mp_join_syns.sender_truncated_mac;
			mpj->u.synack.nonce = opts->mp_join_syns.sender_nonce;
			mpj->b = opts->mp_join_syns.low_prio;
			mpj->addr_id = opts->addr_id;
			ptr += MPTCP_SUB_LEN_JOIN_SYNACK_ALIGN >> 2;
		} else if (OPTION_TYPE_ACK & opts->mptcp_options) {
			mpj->len = MPTCP_SUB_LEN_JOIN_ACK;
			mpj->addr_id = 0; /* addr_id is rsv (RFC 6824, p. 21) */
			memcpy(mpj->u.ack.mac, &tp->mptcp->sender_mac[0], 20);
			ptr += MPTCP_SUB_LEN_JOIN_ACK_ALIGN >> 2;
		}
	}
	/* 携带ADD_ADDR情况，通知对端增加新的IP，rfc6824 3.4.1节 */
	if (unlikely(OPTION_ADD_ADDR & opts->mptcp_options)) {
		struct mp_add_addr *mpadd = (struct mp_add_addr *)ptr;
		struct mptcp_cb *mpcb = tp->mpcb;

		mpadd->kind = TCPOPT_MPTCP;/* kind=30 */
		if (opts->add_addr_v4) {
			/* subtype MPTCP_SUB_ADD_ADDR=3表示ADD_ADDR rfc6824 3.4.1节 */
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 4;
			mpadd->addr_id = opts->add_addr4.addr_id;
			mpadd->u.v4.addr = opts->add_addr4.addr;
			if (mpcb->mptcp_ver < MPTCP_VERSION_1) {
				mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4;
				ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN >> 2;
			} else {
				memcpy((char *)mpadd->u.v4.mac - 2,
				       (char *)&opts->add_addr4.trunc_mac, 8);
				mpadd->len = MPTCP_SUB_LEN_ADD_ADDR4_VER1;
				ptr += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1 >> 2;
			}
		} else if (opts->add_addr_v6) {
			/* subtype MPTCP_SUB_ADD_ADDR=3表示ADD_ADDR rfc6824 3.4.1节 */
			mpadd->sub = MPTCP_SUB_ADD_ADDR;
			mpadd->ipver = 6;
			mpadd->addr_id = opts->add_addr6.addr_id;
			memcpy(&mpadd->u.v6.addr, &opts->add_addr6.addr,
			       sizeof(mpadd->u.v6.addr));
			if (mpcb->mptcp_ver < MPTCP_VERSION_1) {
				mpadd->len = MPTCP_SUB_LEN_ADD_ADDR6;
				ptr += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN >> 2;
			} else {
				memcpy((char *)mpadd->u.v6.mac - 2,
				       (char *)&opts->add_addr6.trunc_mac, 8);
				mpadd->len = MPTCP_SUB_LEN_ADD_ADDR6_VER1;
				ptr += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN_VER1 >> 2;
			}
		}

		MPTCP_INC_STATS(sock_net((struct sock *)tp), MPTCP_MIB_ADDADDRTX);
	}
	/* 携带Remove Address情况，通知对端删除IP，rfc6824 3.4.2节 */
	if (unlikely(OPTION_REMOVE_ADDR & opts->mptcp_options)) {
		struct mp_remove_addr *mprem = (struct mp_remove_addr *)ptr;
		u8 *addrs_id;
		int id, len, len_align;

		len = mptcp_sub_len_remove_addr(opts->remove_addrs);
		len_align = mptcp_sub_len_remove_addr_align(opts->remove_addrs);

		mprem->kind = TCPOPT_MPTCP;/* kind=30 */
		mprem->len = len;
		/* subtype MPTCP_SUB_ADD_ADDR=4表示REMOVE_ADDR rfc6824 3.4.2节 */
		mprem->sub = MPTCP_SUB_REMOVE_ADDR;
		mprem->rsv = 0;
		addrs_id = &mprem->addrs_id;

		mptcp_for_each_bit_set(opts->remove_addrs, id)
			*(addrs_id++) = id;

		/* Fill the rest with NOP's */
		if (len_align > len) {
			int i;
			for (i = 0; i < len_align - len; i++)
				*(addrs_id++) = TCPOPT_NOP;
		}

		ptr += len_align >> 2;

		MPTCP_INC_STATS(sock_net((struct sock *)tp), MPTCP_MIB_REMADDRTX);
	}
    /* 携带MP_FAIL情况，MPTCP不可用，fallback回SPTCP，rfc6824 3.6节 */
	if (unlikely(OPTION_MP_FAIL & opts->mptcp_options)) {
		struct mp_fail *mpfail = (struct mp_fail *)ptr;

		mpfail->kind = TCPOPT_MPTCP;/* kind=30 */
		mpfail->len = MPTCP_SUB_LEN_FAIL;
		/* subtype MPTCP_SUB_FAIL=6表示MP_FAIL rfc6824 3.6节 */
		mpfail->sub = MPTCP_SUB_FAIL;
		mpfail->rsv1 = 0;
		mpfail->rsv2 = 0;
		mpfail->data_seq = htonll(tp->mpcb->csum_cutoff_seq);

		ptr += MPTCP_SUB_LEN_FAIL_ALIGN >> 2;
	}
	/* 携带MP_FASTCLOSE情况，fast close，rfc6824 3.5节 */
	if (unlikely(OPTION_MP_FCLOSE & opts->mptcp_options)) {
		struct mp_fclose *mpfclose = (struct mp_fclose *)ptr;

		mpfclose->kind = TCPOPT_MPTCP;/* kind=30 */
		mpfclose->len = MPTCP_SUB_LEN_FCLOSE;
		/* subtype MPTCP_SUB_FCLOSE=7表示MP_FASTCLOSE rfc6824 3.5节 */
		mpfclose->sub = MPTCP_SUB_FCLOSE;
		mpfclose->rsv1 = 0;
		mpfclose->rsv2 = 0;
		mpfclose->key = opts->mp_capable.receiver_key;

		ptr += MPTCP_SUB_LEN_FCLOSE_ALIGN >> 2;
	}
	/* 携带DSS情况，Data Sequence Signal(DATA ACK和DSM)，rfc6824 3.3节 */
	if (OPTION_DATA_ACK & opts->mptcp_options) {
		/* subtype MPTCP_SUB_DSS=2表示DSS，有2部分内容，DATA ACK和
		DSM - data sequence mapping rfc6824 3.3节 */
		if (!mptcp_is_data_seq(skb))
			ptr += mptcp_write_dss_data_ack(tp, skb, ptr);/* 详见下 */
		else
			ptr += mptcp_write_dss_data_seq(tp, skb, ptr);/* 详见下 */
	}
	/* 携带MP_PRIO情况，改变subflow优先级，rfc6824 3.3.8节 */
	if (unlikely(OPTION_MP_PRIO & opts->mptcp_options)) {
		struct mp_prio *mpprio = (struct mp_prio *)ptr;

		mpprio->kind = TCPOPT_MPTCP;/* kind=30 */
		mpprio->len = MPTCP_SUB_LEN_PRIO;
		/* subtype MPTCP_SUB_PRIO=5表示MP_PRIO rfc6824 3.3.8节 */
		mpprio->sub = MPTCP_SUB_PRIO;
		mpprio->rsv = 0;
		mpprio->b = tp->mptcp->low_prio;
		mpprio->addr_id = TCPOPT_NOP;

		ptr += MPTCP_SUB_LEN_PRIO_ALIGN >> 2;
	}
}
```



```c
static int mptcp_write_dss_data_ack(const struct tcp_sock *tp, const struct sk_buff *skb,
				    __be32 *ptr)
{
	struct mp_dss *mdss = (struct mp_dss *)ptr;
	__be32 *start = ptr;

	mdss->kind = TCPOPT_MPTCP;/* kind=30 */
	/* subtype MPTCP_SUB_DSS=2表示DSS，有2部分内容，DATA ACK和
		DSM - data sequence mapping rfc6824 3.3节 */
	mdss->sub = MPTCP_SUB_DSS;
	mdss->rsv1 = 0;
	mdss->rsv2 = 0;
	mdss->F = mptcp_is_data_fin(skb) ? 1 : 0; /* 1表示DATA_FIN也就是最后一包数据 */
	mdss->m = 0; /* 0表示DSN是4字节长，1表示DSN是8字节长。m位只有M位置位才有效 */
    /* M位置1表示携带DSM，DSM由DSN(Data Sequence Number)，SSN(Subflow Sequence Number)
    Data-Level Length和Checksum组成 */
	mdss->M = mptcp_is_data_seq(skb) ? 1 : 0;
	mdss->a = 0; /* 0表示DATA ACK是4字节，1表示是8字节。a位只有A位置1才有效。 */
	mdss->A = 1; /* 1表示携带了Data ACK */
	mdss->len = mptcp_sub_len_dss(mdss, tp->mpcb->dss_csum);
	ptr++;

	*ptr++ = htonl(mptcp_meta_tp(tp)->rcv_nxt);

	return ptr - start;
}
```



```c
/* Write the saved DSS mapping to the header */
static int mptcp_write_dss_data_seq(const struct tcp_sock *tp, struct sk_buff *skb,
				    __be32 *ptr)
{
	__be32 *start = ptr;
	/* TCP_SKB_CB(skb)->dss存的就是dss subtype的信息，所以没有类似
	mptcp_write_dss_data_ack中的设置代码。那TCP_SKB_CB(skb)->dss是在何处存的呢？
	是在mptcp_skb_entail->mptcp_save_dss_data_seq进行保存，详情参考这两个函数的分析。 */
	memcpy(ptr, TCP_SKB_CB(skb)->dss, mptcp_dss_len);

	/* update the data_ack */
	start[1] = htonl(mptcp_meta_tp(tp)->rcv_nxt);

	/* dss is in a union with inet_skb_parm and
	 * the IP layer expects zeroed IPCB fields.
	 */
	memset(TCP_SKB_CB(skb)->dss, 0 , mptcp_dss_len);

	return mptcp_dss_len/sizeof(*ptr);
}
```

返回 [tcp_options_write](MPTCP-tcp_options_write.html)