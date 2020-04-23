---
layout: default
title:  "tcp_send_syn_data hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_output.c */ /* TODO */
/* Build and send a SYN with data and (cached) Fast Open cookie. However,
 * queue a data-only packet after the regular SYN, such that regular SYNs
 * are retransmitted on timeouts. Also if the remote SYN-ACK acknowledges
 * only the SYN sequence, the data are retransmitted in the first ACK.
 * If cookie is not cached or other error occurs, falls back to send a
 * regular SYN with Fast Open cookie request option.
 */
static int tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int space, err = 0;
	struct sk_buff *syn_data;

	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	if (!tcp_fastopen_cookie_check(sk, &tp->rx_opt.mss_clamp, &fo->cookie))
		goto fallback;

	/* MSS for SYN-data is based on cached MSS and bounded by PMTU and
	 * user-MSS. Reserve maximum option space for middleboxes that add
	 * private TCP options. The cost is reduced data space in SYN :(
	 */
	tp->rx_opt.mss_clamp = tcp_mss_clamp(tp, tp->rx_opt.mss_clamp);

	space = __tcp_mtu_to_mss(sk, inet_csk(sk)->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	space = min_t(size_t, space, fo->size);

	/* limit to order-0 allocations */
	space = min_t(size_t, space, SKB_MAX_HEAD(MAX_TCP_HEADER));

	syn_data = sk_stream_alloc_skb(sk, space, sk->sk_allocation, false);
	if (!syn_data)
		goto fallback;
	syn_data->ip_summed = CHECKSUM_PARTIAL;
	memcpy(syn_data->cb, syn->cb, sizeof(syn->cb));
	if (space) {
		int copied = copy_from_iter(skb_put(syn_data, space), space,
					    &fo->data->msg_iter);
		if (unlikely(!copied)) {
			tcp_skb_tsorted_anchor_cleanup(syn_data);
			kfree_skb(syn_data);
			goto fallback;
		}
		if (copied != space) {
			skb_trim(syn_data, copied);
			space = copied;
		}
	}
	/* No more data pending in inet_wait_for_connect() */
	if (space == fo->size)
		fo->data = NULL;
	fo->copied = space;

	tcp_connect_queue_skb(sk, syn_data);
	if (syn_data->len)
		tcp_chrono_start(sk, TCP_CHRONO_BUSY);

	err = tcp_transmit_skb(sk, syn_data, 1, sk->sk_allocation);

	syn->skb_mstamp = syn_data->skb_mstamp;

	/* Now full SYN+DATA was cloned and sent (or not),
	 * remove the SYN from the original skb (syn_data)
	 * we keep in write queue in case of a retransmit, as we
	 * also have the SYN packet (with no data) in the same queue.
	 */
	TCP_SKB_CB(syn_data)->seq++;
	TCP_SKB_CB(syn_data)->tcp_flags = TCPHDR_ACK | TCPHDR_PSH;
	if (!err) {
		tp->syn_data = (fo->copied > 0);
		tcp_rbtree_insert(&sk->tcp_rtx_queue, syn_data);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT);
		goto done;
	}

	/* data was not sent, put it in write_queue */
	__skb_queue_tail(&sk->sk_write_queue, syn_data);
	tp->packets_out -= tcp_skb_pcount(syn_data);

fallback:
	/* Send a regular SYN with Fast Open cookie request option */
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	err = tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		tp->syn_fastopen = 0;
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}
```

```c
/* net/ipv4/tcp_fastopen.c */
bool tcp_fastopen_cookie_check(struct sock *sk, u16 *mss,
			       struct tcp_fastopen_cookie *cookie)
{
	const struct dst_entry *dst;

	tcp_fastopen_cache_get(sk, mss, cookie);

	/* Firewall blackhole issue check */
	if (tcp_fastopen_active_should_disable(sk)) {
		cookie->len = -1;
		return false;
	}

	dst = __sk_dst_get(sk);

	if (tcp_fastopen_no_cookie(sk, dst, TFO_CLIENT_NO_COOKIE)) {
		cookie->len = -1;
		return true;
	}
	return cookie->len > 0;
}
```

返回 [tcp_connect](MPTCP-tcp_connect.html)

