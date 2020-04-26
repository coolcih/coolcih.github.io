---
layout: default
title:  "tcp_push hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp.c */
static void tcp_push(struct sock *sk, int flags, int mss_now,
		     int nonagle, int size_goal)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	skb = tcp_write_queue_tail(sk);
	if (!skb)
		return;
	if (!(flags & MSG_MORE) || forced_push(tp))
		tcp_mark_push(tp, skb);

	tcp_mark_urg(tp, flags);

	if (tcp_should_autocork(sk, skb, size_goal)) {

		/* avoid atomic op if TSQ_THROTTLED bit is already set */
		if (!test_bit(TSQ_THROTTLED, &sk->sk_tsq_flags)) {
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTOCORKING);
			set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
		}
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED.
		 */
		if (refcount_read(&sk->sk_wmem_alloc) > skb->truesize)
			return;
	}

	if (flags & MSG_MORE)
		nonagle = TCP_NAGLE_CORK;

	__tcp_push_pending_frames(sk, mss_now, nonagle);
}
```

```c
/* net/ipv4/tcp_output.c */
/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_sk(sk)->ops->write_xmit(sk, cur_mss, nonagle, 0,
					sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}
```

![tcpsenddataflow](../../../../../images/tcpsenddataflow.jpg)

<p style="text-align:center">图1 数据发送流程</p>

返回 [tcp_sendmsg](MPTCP-code-study-datatransfer.html)