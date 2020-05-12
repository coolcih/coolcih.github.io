---
layout: default
title:  "mptcp_write_xmit hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/mptcp/mptcp_output.c */
bool mptcp_write_xmit(struct sock *meta_sk, unsigned int mss_now, int nonagle,
		     int push_one, gfp_t gfp)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk), *subtp;
	struct mptcp_tcp_sock *mptcp;
	struct sock *subsk = NULL;
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	int reinject = 0;
	unsigned int sublimit;
	__u32 path_mask = 0;

	tcp_mstamp_refresh(meta_tp);

	if (inet_csk(meta_sk)->icsk_retransmits) {
		/* If the timer already once fired, retransmit the head of the
		 * queue to unblock us ASAP.
		 */
		if (meta_tp->packets_out && !mpcb->infinite_mapping_snd)
			mptcp_retransmit_skb(meta_sk, tcp_rtx_queue_head(meta_sk));
	}

	while ((skb = mpcb->sched_ops->next_segment(meta_sk, &reinject, &subsk,
						    &sublimit))) {
		enum tcp_queue tcp_queue = TCP_FRAG_IN_WRITE_QUEUE;
		unsigned int limit;

		WARN(TCP_SKB_CB(skb)->sacked, "sacked: %u reinject: %u",
		     TCP_SKB_CB(skb)->sacked, reinject);

		subtp = tcp_sk(subsk);
		mss_now = tcp_current_mss(subsk);

		if (reinject == 1) {
			if (!after(TCP_SKB_CB(skb)->end_seq, meta_tp->snd_una)) {
				/* Segment already reached the peer, take the next one */
				__skb_unlink(skb, &mpcb->reinject_queue);
				__kfree_skb(skb);
				continue;
			}
		} else if (reinject == -1) {
			tcp_queue = TCP_FRAG_IN_RTX_QUEUE;
		}

		/* If the segment was cloned (e.g. a meta retransmission),
		 * the header must be expanded/copied so that there is no
		 * corruption of TSO information.
		 */
		if (skb_unclone(skb, GFP_ATOMIC))
			break;

		if (unlikely(!tcp_snd_wnd_test(meta_tp, skb, mss_now)))
			break;

		/* Force tso_segs to 1 by using UINT_MAX.
		 * We actually don't care about the exact number of segments
		 * emitted on the subflow. We need just to set tso_segs, because
		 * we still need an accurate packets_out count in
		 * tcp_event_new_data_sent.
		 */
		tcp_set_skb_tso_segs(skb, UINT_MAX);

		/* Check for nagle, irregardless of tso_segs. If the segment is
		 * actually larger than mss_now (TSO segment), then
		 * tcp_nagle_check will have partial == false and always trigger
		 * the transmission.
		 * tcp_write_xmit has a TSO-level nagle check which is not
		 * subject to the MPTCP-level. It is based on the properties of
		 * the subflow, not the MPTCP-level.
		 * When the segment is a reinjection or redundant scheduled
		 * segment, nagle check at meta-level may prevent
		 * sending. This could hurt with certain schedulers, as they
		 * to reinjection to recover from a window-stall or reduce latency.
		 * Therefore, Nagle check should be disabled in that case.
		 */
		if (!reinject &&
		    unlikely(!tcp_nagle_test(meta_tp, skb, mss_now,
					     (tcp_skb_is_last(meta_sk, skb) ?
					      nonagle : TCP_NAGLE_PUSH))))
			break;

		limit = mss_now;
		/* skb->len > mss_now is the equivalent of tso_segs > 1 in
		 * tcp_write_xmit. Otherwise split-point would return 0.
		 */
		if (skb->len > mss_now && !tcp_urg_mode(meta_tp))
			/* We limit the size of the skb so that it fits into the
			 * window. Call tcp_mss_split_point to avoid duplicating
			 * code.
			 * We really only care about fitting the skb into the
			 * window. That's why we use UINT_MAX. If the skb does
			 * not fit into the cwnd_quota or the NIC's max-segs
			 * limitation, it will be split by the subflow's
			 * tcp_write_xmit which does the appropriate call to
			 * tcp_mss_split_point.
			 */
			limit = tcp_mss_split_point(meta_sk, skb, mss_now,
						    UINT_MAX / mss_now,
						    nonagle);

		if (sublimit)
			limit = min(limit, sublimit);

		if (skb->len > limit &&
		    unlikely(mptcp_fragment(meta_sk, tcp_queue,
					    skb, limit, gfp, reinject)))
			break;

		if (!mptcp_skb_entail(subsk, skb, reinject))
			break;
		/* Nagle is handled at the MPTCP-layer, so
		 * always push on the subflow
		 */
		__tcp_push_pending_frames(subsk, mss_now, TCP_NAGLE_PUSH);
		if (reinject <= 0)
			tcp_update_skb_after_send(meta_tp, skb);
		meta_tp->lsndtime = tcp_jiffies32;

		path_mask |= mptcp_pi_to_flag(subtp->mptcp->path_index);

		if (!reinject) {
			mptcp_check_sndseq_wrap(meta_tp,
						TCP_SKB_CB(skb)->end_seq -
						TCP_SKB_CB(skb)->seq);
			tcp_event_new_data_sent(meta_sk, skb);
		}

		tcp_minshall_update(meta_tp, mss_now, skb);

		if (reinject > 0) {
			__skb_unlink(skb, &mpcb->reinject_queue);
			kfree_skb(skb);
		}

		if (push_one)
			break;
	}

	mptcp_for_each_sub(mpcb, mptcp) {
		subsk = mptcp_to_sock(mptcp);
		subtp = tcp_sk(subsk);

		if (!(path_mask & mptcp_pi_to_flag(subtp->mptcp->path_index)))
			continue;

		/* We have pushed data on this subflow. We ignore the call to
		 * cwnd_validate in tcp_write_xmit as is_cwnd_limited will never
		 * be true (we never push more than what the cwnd can accept).
		 * We need to ensure that we call tcp_cwnd_validate with
		 * is_cwnd_limited set to true if we have filled the cwnd.
		 */
		tcp_cwnd_validate(subsk, tcp_packets_in_flight(subtp) >=
				  subtp->snd_cwnd);
	}

	return !meta_tp->packets_out && tcp_send_head(meta_sk);
}
```

[mptcp_connect_init](MPTCP-mptcp_connect_init.html)

返回 [tcp_push](MPTCP-tcp_push.html)

