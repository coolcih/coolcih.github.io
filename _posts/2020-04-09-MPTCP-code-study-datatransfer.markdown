---
layout: post
title:  "MPTCP代码分析 - MPTCP能力协商，数据发送流程"
date:   2020-04-09 12:06:58 +0800
categories: Network technology
---




```c
/* net/ipv4/tcp.c */
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int ret;

	lock_sock(sk);
	ret = tcp_sendmsg_locked(sk, msg, size);/* 详见下 */
	release_sock(sk);

	return ret;
}
```



```c
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;
	struct sockcm_cookie sockc;
	int flags, err, copied = 0;
	int mss_now = 0, size_goal, copied_syn = 0;
	bool process_backlog = false;
	bool zc = false;
	long timeo;

	flags = msg->msg_flags;

	if (flags & MSG_ZEROCOPY && size && sock_flag(sk, SOCK_ZEROCOPY)) {
		if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
			err = -EINVAL;
			goto out_err;
		}

		skb = tcp_write_queue_tail(sk);
		uarg = sock_zerocopy_realloc(sk, size, skb_zcopy(skb));
		if (!uarg) {
			err = -ENOBUFS;
			goto out_err;
		}

		zc = sk->sk_route_caps & NETIF_F_SG;
		if (!zc)
			uarg->zerocopy = 0;
	}

	if (unlikely(flags & MSG_FASTOPEN || inet_sk(sk)->defer_connect) &&
	    !tp->repair) {
		err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(mptcp(tp) && tp->mpcb->master_sk ?
				  tp->mpcb->master_sk : sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}

	if (mptcp(tp)) {
		struct mptcp_tcp_sock *mptcp;

		mptcp_for_each_sub(tp->mpcb, mptcp) {
			sock_rps_record_flow(mptcp_to_sock(mptcp));
		}
	}

	if (unlikely(tp->repair)) {
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			copied = tcp_send_rcvq(sk, msg, size);
			goto out_nopush;
		}

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;

		/* 'common' sending to sendq */
	}

	sockcm_init(&sockc, sk);
	if (msg->msg_controllen) {
		err = sock_cmsg_send(sk, msg, &sockc);
		if (unlikely(err)) {
			err = -EINVAL;
			goto out_err;
		}
	}

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Ok commence sending. */
	copied = 0;

restart:
	mss_now = tcp_send_mss(sk, &size_goal, flags);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (msg_data_left(msg)) {
		int copy = 0;

		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;

		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) {
			bool first_skb;
			int linear;

new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			if (process_backlog && sk_flush_backlog(sk)) {
				process_backlog = false;
				goto restart;
			}
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			linear = tp->ops->select_size(sk, first_skb, zc);
			skb = sk_stream_alloc_skb(sk, linear, sk->sk_allocation,
						  first_skb);
			if (!skb)
				goto wait_for_memory;

			process_backlog = true;
			skb->ip_summed = CHECKSUM_PARTIAL;

			skb_entail(sk, skb);
			copy = size_goal;

			/* All packets are restored as if they have
			 * already been sent. skb_mstamp isn't set to
			 * avoid wrong rtt estimation.
			 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);

		/* Where to copy to? */
		if (skb_availroom(skb) > 0 && !zc) {
			/* We have some space in skb head. Superb! */
			copy = min_t(int, copy, skb_availroom(skb));
			err = skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
			if (err)
				goto do_fault;
		} else if (!zc) {
			bool merge = true;
			int i = skb_shinfo(skb)->nr_frags;
			struct page_frag *pfrag = sk_page_frag(sk);

			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_memory;

			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				if (i >= sysctl_max_skb_frags) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				}
				merge = false;
			}

			copy = min_t(int, copy, pfrag->size - pfrag->offset);

			if (!sk_wmem_schedule(sk, copy))
				goto wait_for_memory;

			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			if (err)
				goto do_error;

			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}
			pfrag->offset += copy;
		} else {
			err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg);
			if (err == -EMSGSIZE || err == -EEXIST) {
				tcp_mark_push(tp, skb);
				goto new_segment;
			}
			if (err < 0)
				goto do_error;
			copy = err;
		}

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		tcp_skb_pcount_set(skb, 0);

		copied += copy;
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		}

		if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now,
				 TCP_NAGLE_PUSH, size_goal);

		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied) {
		tcp_tx_timestamp(sk, sockc.tsflags);
		tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);
	}
out_nopush:
	sock_zerocopy_put(uarg);
	return copied + copied_syn;

do_error:
	skb = tcp_write_queue_tail(sk);
do_fault:
	tcp_remove_empty_skb(sk, skb);

	if (copied + copied_syn)
		goto out;
out_err:
	sock_zerocopy_put_abort(uarg);
	err = sk_stream_error(sk, flags, err);
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 &&
		     err == -EAGAIN)) {
		sk->sk_write_space(sk);
		tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
	return err;
}
```

[ip_route_connect](MPTCP-ip_route_connect.html)

[tcp_connect](MPTCP-tcp_connect.html)

<a href="{{ "/" | relative_url }}">{{ "返回主页" | escape }}</a>