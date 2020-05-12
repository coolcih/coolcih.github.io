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
	/* write_xmit在不支持MPTCP的情况就是tcp sock的操作，也就是指向函数
	tcp_write_xmit。但在支持MPTCP的情况，要看sk是那层的sock，如果是MPTCP层
	的sock，ops就是mptcp_ctrl.c::mptcp_meta_specific。如果是TCP subflow
	层的sock，ops就是mptcp_ctrl.c::mptcp_sub_specific。安装MPTCP设计，
	MPTCP层位于tcp subflow层上面，所以数据应是先流经MPTCP层，然后才到subflow
	层，所以这里write_xmit应该调用的是MPTCP层的mptcp_write_xmit。 
	mptcp_write_xmit详情点击下面链接。 下文会详述meta tcp sock ops和subflow 
	tcp sock ops的设置过程。	*/
	if (tcp_sk(sk)->ops->write_xmit(sk, cur_mss, nonagle, 0,
					sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}
```

[mptcp_write_xmit](MPTCP-mptcp_write_xmit.html)

![tcpsenddataflow](../../../../../images/tcpsenddataflow.png)

<p style="text-align:center">图1 数据发送流程</p>

```c
/* net/mptcp/mptcp_ctrl.c */
/* mptcp meta tcp sock的操作，meta在MPTCP上下文中就是指MPTCP层 */
static const struct tcp_sock_ops mptcp_meta_specific = {
	.__select_window		= __mptcp_select_window,
	.select_window			= mptcp_select_window,
	.select_initial_window		= mptcp_select_initial_window,
	.select_size			= mptcp_select_size,
	.init_buffer_space		= mptcp_init_buffer_space,
	.set_rto			= mptcp_tcp_set_rto,
	.should_expand_sndbuf		= mptcp_should_expand_sndbuf,
	.send_fin			= mptcp_send_fin,
	.write_xmit			= mptcp_write_xmit,
	.send_active_reset		= mptcp_send_active_reset,
	.write_wakeup			= mptcp_write_wakeup,
	.retransmit_timer		= mptcp_meta_retransmit_timer,
	.time_wait			= mptcp_time_wait,
	.cleanup_rbuf			= mptcp_cleanup_rbuf,
	.set_cong_ctrl                  = mptcp_set_congestion_control,
};

/* MPTCP subflow tcp sock的操作，subflow在MPTCP上下文中指MPTCP层的下层，
也就是TCP subflow层。 从操作指向的函数看subflow层和TCP层很类似了，尤其传输
函数直接就是tcp的函数，例如tcp_write_xmit。 */
static const struct tcp_sock_ops mptcp_sub_specific = {
	.__select_window		= __mptcp_select_window,
	.select_window			= mptcp_select_window,
	.select_initial_window		= mptcp_select_initial_window,
	.select_size			= mptcp_select_size,
	.init_buffer_space		= mptcp_init_buffer_space,
	.set_rto			= mptcp_tcp_set_rto,
	.should_expand_sndbuf		= mptcp_should_expand_sndbuf,
	.send_fin			= tcp_send_fin,
	.write_xmit			= tcp_write_xmit,
	.send_active_reset		= tcp_send_active_reset,
	.write_wakeup			= tcp_write_wakeup,
	.retransmit_timer		= mptcp_sub_retransmit_timer,
	.time_wait			= tcp_time_wait,
	.cleanup_rbuf			= tcp_cleanup_rbuf,
	.set_cong_ctrl                  = __tcp_set_congestion_control,
};

static int mptcp_alloc_mpcb(struct sock *meta_sk, __u64 remote_key,
			    __u8 mptcp_ver, u32 window)
{	
    /* meta_sk是MPTCP层的sock，它对应的tcp_sock是meta_tp */
    struct tcp_sock *master_tp, *meta_tp = tcp_sk(meta_sk);
    
    /* 根据meta_sk，复制了一个sock，作为master sock，所谓master sock就是
    第一个TCP subflow的sock，所以master sock是一个真正的TCP sock(如下，可
    以看到它ops是指向tcp相关的函数)。而meta sock虽然从应用的角度好像一个TCP 
    sock，但它实际上是一个MPTCP sock(如下，可以看到它ops还是指向MPTCP相关的函数)，
    从分层的角度meta sock位于master sock上层，从函数调用流程，发送数据时会先调用
    到meta sock ops指向的mptcp相关的函数，然后在这些mptcp函数内部通过master sock
    ops调用tcp相关函数进行传输。上面tcp_push就是一例。 */
    master_sk = sk_clone_lock(meta_sk, GFP_ATOMIC | __GFP_ZERO);
    
	/* 创建mptcp_cb */
	mpcb = kmem_cache_zalloc(mptcp_cb_cache, GFP_ATOMIC);
    
	/* 在mpcb中分别记录meta sock和master sock */
	mpcb->meta_sk = meta_sk;
	mpcb->master_sk = master_sk;
    
	/* Set mptcp-pointers */
	/* master tcp sock和meta tcp sock记录mpcb和meta sock 
	记录mpcb很关键，meta tcp sock要通过mpcb才能找到master sock
	所以通过此处赋值，把这些sock关联起来。 */
	master_tp->mpcb = mpcb;
	master_tp->meta_sk = meta_sk;
	meta_tp->mpcb = mpcb;
	meta_tp->meta_sk = meta_sk;
    
	/* 设置mptcp tcp sock(meta sock)操作 */
	meta_tp->ops = &mptcp_meta_specific;
}

/* 此函数主要对第二个参数传入的sock进行初始化，例如设置对应的ops，关联mpcb等。 */
int mptcp_add_sock(struct sock *meta_sk, struct sock *sk, u8 loc_id, u8 rem_id,
		   gfp_t flags)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
    /* tp取自第二个参数sk，而不是第一个参数meta_sk，这很关键，说明
    tp不是指mptcp层的tcp sock，具体是谁的sock，要看mptcp_add_sock调用者
    下面mptcp_create_master_sk中会看的更清楚。 */
	struct tcp_sock *tp = tcp_sk(sk);

	/* 从这个赋值大体可以猜出传入的sk(第二个参数)应该代表的是MPTCP的一个subflow，否则
	不会设置mptcp subflow的操作mptcp_sub_specific，这点在下面mptcp_create_master_sk
	会印证。 */
	tp->ops = &mptcp_sub_specific;
}

int mptcp_create_master_sk(struct sock *meta_sk, __u64 remote_key,
			   __u8 mptcp_ver, u32 window)
{
	struct tcp_sock *master_tp;
	struct sock *master_sk;
    
	/* 由上可知，此函数负责：
	1. 根据meta sock克隆一个master sock
	2. 创建一个mpcb
	3. 把mpcb，meta sock以及对应的tcp sock，master sock以及对应的tcp sock
	都关联起来。 */
	if (mptcp_alloc_mpcb(meta_sk, remote_key, mptcp_ver, window))
		goto err_alloc_mpcb;
    
	/* 因为mptcp_alloc_mpcb进行了关联，可以通过meta sock找到对应的master sock
	以及master sock对应的tcp sock。 */
	master_sk = tcp_sk(meta_sk)->mpcb->master_sk;
	master_tp = tcp_sk(master_sk);
	
    /* 可以看到master sock作为第二个参数传入了，而master sock就是
    MPTCP的第一个tcp subflow sock。印证了前面mptcp_add_sock中的
    猜测。 */
    if (mptcp_add_sock(meta_sk, master_sk, 0, 0, GFP_ATOMIC))
		goto err_add_sock;
}
```

返回 [tcp_sendmsg](MPTCP-code-study-datatransfer.html)