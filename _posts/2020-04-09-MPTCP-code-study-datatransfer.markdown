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
	/* 计算超时时间，如果flags设置了MSG_DONTWAIT标记，则超时时间为0 */
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	/* 只有ESTABLISHED和CLOSE_WAIT两个状态可以发送数据，其它状态需要等待连接完成；
	CLOSE_WAIT是收到对端FIN但是本端还没有发送FIN时所处状态，所以也可以发送数据。
	但对于对端请求fast open，也就是passive fast open场景是例外，这种场景在本端收到
	SYN后，就可以发送数据，也就是上面源码注释提到的"allowed to be sent before a 
	connection is fully established"。 对于MPTCP，判断是否是passive fast open
	时，要传入主sock。*/
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(mptcp(tp) && tp->mpcb->master_sk ?
				  tp->mpcb->master_sk : sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}

	/* 记录rps，关于rps TODO */
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
	/* 调用tcp_send_mss获取当前有效mss即mss_now和数据段的最大长度即size_goal。
	在此传入是否标识MSG_OOB位，这是因为MSG_OOB是判断是否支持GSO的条件之一，
	而紧急数据不支持GSO。
	mss_now:当前的最大报文分段长度(Maxitum Segment Size)。
	size_goal:发送数据报到达网络设备时数据段的最大长度，该长度用来分割数据。TCP发
	送报文时，每个SKB的大小不能超过该值。在不支持GSO的情况下，size_goal就等于
	mss_now，而如果支持GSO，则size_goal会是MSS的整数倍。数据报发送到网络设备
	后再由网络设备根据MSS进行分割。
	对于MPTCP，使用mptcp_current_mss和mptcp_xmit_size_goal
	计算mss_now和size_goal。对于SPTCP，使用tcp_current_mss和
	tcp_xmit_size_goal计算mss_now和size_goal。*/
	mss_now = tcp_send_mss(sk, &size_goal, flags);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	/* msg 是用户要写入的数据，这个数据要拷贝到内核协议栈里面去发送；在内核协议栈里面，
	网络包的数据都是由 struct sk_buff 维护的，因而第一件事情就是找到一个空闲的内存空间，
	将用户要写入的数据，拷贝到 struct sk_buff 的管辖范围内。而第二件事情就是发送 struct 
	sk_buff。 while循环检查msg还有数据没有拷贝到sk_buff，则继续拷贝。 */
	while (msg_data_left(msg)) {
		int copy = 0;
		/* TCP写入队列 sk_write_queue 中拿出最后一个 struct sk_buff，在这个写入
		队列中排满了要发送的 struct sk_buff，为什么要拿最后一个呢？这里面只有最后一
		个，可能会因为上次用户给的数据太少，而没有填满*/
		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;/* size_goal是分割数据的最大长度，
			skb->len则是一个sk buffer的长度，skb->len要和size_goal匹配。所以
			要对size_goal和skb->len差异进行对比。copy是本次循环要拷贝的数据长度，
			size_goal是当前SKB的最大数据长度，skb->len是当前skb中现有数据长度，
			相减得到当前skb的剩余数据空间，一般情况相减后会是0，因为都是按size_goal
			放数据，放入后skb->len=size_goal。*/

		/* copy<0说明当前skb已经放了长度为size_goal的数据了，不能再放了，因为size_goal
		是网络设备一次可接受的最大数据量。 需要调用sk_stream_alloc_skb，重新分配 
		struct sk_buff，然后调用 skb_entail，将新分配的 sk_buff放到队列尾部 */
		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) {
			bool first_skb;
			int linear;

new_segment:
			/* 如果发送队列的总大小sk_wmem_queued大于等于发送缓存的上限sk_sndbuf， 
			或者发送缓存中尚未发送的数据量超过了用户的设置值，就进入等待。 
			sk_stream_memory_free中两个参数的说明：
			sk->sk_wmem_queued:表示发送缓冲队列中已分配的字节数，一般来说，分配
			一个struct sk_buff是用于存放一个tcp数据报，其分配字节数应该是MSS+协
			议首部长度。例如，size_goal值是1448，协议首部取最大长度
			MAX_TCP_HEADER，假设为224。经数据对齐处理后，最后struct sk_buff的
			truesize为1956。也就是队列中每分配一个struct sk_buff，
			sk->sk_wmem_queued的值就增加1956。
			sk->sk_rcvbuf、sk->sk_sndbuf：这两个值分别代表每个sock的接收发送队
			列的最大限制。*/
			/* TCP/IPV4，此函数会调用tcp.h::tcp_stream_memory_free */
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			if (process_backlog && sk_flush_backlog(sk)) {
				process_backlog = false;
				goto restart;
			}
			/* 判断重传队列和发送队列是否都是空，如果都是返回true，也就是
			first_skb为true，表示这是第一个skb，存TCP报文开始部分。*/
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			/* 通过tcp.c::select_size()得到线性数据区长度。并存于变量linear中。
			如果zc(Zero Copy)=0，则linear=0。
			如果first_skb为false，即不是第一个sbk，则linear=0。
			否则，返回TCP负荷的大小(2048) - 最大的协议头长度 */ 
			linear = tp->ops->select_size(sk, first_skb, zc);
			/* 申请一个skb，其线性数据区的大小为linear。  
			如果申请skb失败了，或者虽然申请skb成功，但是从系统层面判断此次
			申请不合法，那么就进入睡眠，等待内存。 */
			skb = sk_stream_alloc_skb(sk, linear, sk->sk_allocation,
						  first_skb);
			if (!skb)
				goto wait_for_memory;

			process_backlog = true;
			/* 由硬件计算报头和首部的校验和。 */
			skb->ip_summed = CHECKSUM_PARTIAL;
			/* 将该skb插入到发送队列的尾部。 */
			skb_entail(sk, skb);
			/*最后初始化copy变量为发送数据报到网络设备时的最大数据段的长度，
			copy表示每次复制到skb的数据长度。*/
			copy = size_goal;

			/* All packets are restored as if they have
			 * already been sent. skb_mstamp isn't set to
			 * avoid wrong rtt estimation.
			 */
			/* 如果使用了TCP REPAIR选项，那么为skb设置“发送时间”。 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* Try to append data to the end of skb. */
		/* copy不能大于当前数据块剩余待复制的数据长度，如果大于，也就是msg中只剩下最后
		一批数据要拷贝了，讲copy调整成对应值。*/
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);

		/* Where to copy to? */
		/*判断skb的线性存储区底部是否还有空间。而且不是Zero Copy情况 */
		if (skb_availroom(skb) > 0 && !zc) {
			/* We have some space in skb head. Superb! */
			/*要拷贝的数据不能超过线性存储区底部的剩余空间，所以取两者中的小值。 */
			copy = min_t(int, copy, skb_availroom(skb));
			/* 到此为止已经计算除了本次需要复制数据的长度，接下来调用
			skb_add_data_nocache从用户空间复制长度为copy的数据到skb中。
			如果复制失败，则跳转到do_fault处。*/
			err = skb_add_data_nocache(sk, skb, &msg->msg_iter, copy);
			if (err)
				goto do_fault;
		} else if (!zc) {
			/*如果SKB线性存储区底部已经没有空间了，并且不是Zero Copy，即zc=false，
			那就需要把数据复制到支持分散聚合的分页中 */
			/* 为了减少内存拷贝的代价，有的网络设备支持分散聚合(Scatter/Gather)I/O，
			顾名思义，就是 IP 层没必要通过内存拷贝进行聚合，让散的数据零散的放在
			原处，在设备层进行聚合。如果使用这种模式，网络包的数据就不会放在连续的
			数据区域，而是放在 struct skb_shared_info结构里面指向的离散数据，
			skb_shared_info 的成员变量skb_frag_t frags[MAX_SKB_FRAGS]，
			会指向一个数组的页面，就不能保证连续了，参考“图1 sk_buff”。 */
            
			/* merge标识是否在最后一个分页中添加数据 */
			bool merge = true;
 			/*获取当前SKB的分片段数，在skb_shared_info中用nr_frags表示。*/
			int i = skb_shinfo(skb)->nr_frags;
			/* 获取一个分页段 */
			struct page_frag *pfrag = sk_page_frag(sk);

			/* 检查分页是否有可用空间，如果没有就申请新的page。 
			如果申请失败，说明系统内存不足。 
			之后会设置TCP内存压力标志，减小发送缓冲区的上限，睡眠等待内存。 */  
			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_memory;

			/*调用skb_can_coalesce()，判断SKB上最后一个分散聚合页面是否有效，
			即能否将数据添加到该分页上，如果不可以则设置merge标志为false。*/
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				/* 不能追加时，检查分页数是否达到了上限，或者网卡不支持
				分散聚合。 如果是的话，就为此skb设置PSH标志，尽快地发送出去。 
				然后跳转到new_segment处申请新的skb，来继续填装数据。 */
				if (i >= sysctl_max_skb_frags) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				}
				merge = false;/* 设置merge标志为false，
						也就是不可在分页中添加数据。 */
			}
			/* 拷贝的数据不能超过分页的容量 */
			copy = min_t(int, copy, pfrag->size - pfrag->offset);

			if (!sk_wmem_schedule(sk, copy))
				goto wait_for_memory;
			/* 将msg中的copy个数据拷贝进分页，拷贝用户空间的数据到内核空间，
			同时计算校验和。 更新skb的长度字段，更新sock的发送队列大小和预
			分配缓存。 */
			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			if (err)
				goto do_error;

			/* Update the skb. */
			if (merge) {/* 如果把数据追加到最后一个分页了，
					更新最后一个分页的数据大小 */ 
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				/* 初始化新增加的页 */
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}
			pfrag->offset += copy;
		} else {/* Zero Copy的情况 */
			err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg);
			if (err == -EMSGSIZE || err == -EEXIST) {
				tcp_mark_push(tp, skb);
				goto new_segment;
			}
			if (err < 0)
				goto do_error;
			copy = err;
		}
		/* 如果这是第一次拷贝，取消PSH标志 */
		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		tp->write_seq += copy;/* 更新发送队列的最后一个序号 */
		TCP_SKB_CB(skb)->end_seq += copy;/* 更新skb的结束序号 */
		tcp_skb_pcount_set(skb, 0);

		copied += copy;/* 下次拷贝的地址 */ 
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		}

		/* 如果skb还可以继续填充数据，或者发送的是带外数据，或者使用TCP REPAIR选项， 
		那么继续拷贝数据，先不发送。 */
		if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
			continue;

		/* 如果需要设置PUSH标志位，那么设置PUSH，然后发送数据包，
		PUSH可以让TCP尽快的发送数据 */
		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			/* 尽可能的将发送队列中的skb发送出去，禁用nalge */
            /* 函数详情点下面链接 */
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == tcp_send_head(sk))
			/* 当前只有这一个skb，也发送出去。因为只有一个，
			所以肯定也不存在拥塞，可以发送 */
			tcp_push_one(sk, mss_now);
		/* 继续拷贝数据 */
		continue;

wait_for_sndbuf:
		/* 设置套接字结构中发送缓存不足的标志 */
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		 /* 如果已经有数据复制到发送队列了，调用tcp_push
		 尝试立即发送，这样可能可以让发送缓存快速的有剩余
		 空间可用*/
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now,
				 TCP_NAGLE_PUSH, size_goal);/* 函数详情点下面链接 */
		/* 等待有空余内存可以使用，如果timeo不为0，那么这一步会休眠，
		分两种情况： 
		1. sock的发送缓存不足。等待sock有发送缓存可写事件，或者超时。 
		2. TCP层内存不足，等待2~202ms之间的一个随机时间。 */  
		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;
		/* 睡眠后MSS和TSO段长可能会发生变化，重新计算 */ 
		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

out:
	/* 如果已经有数据复制到发送队列了，就尝试立即发送 */
	if (copied) {
		tcp_tx_timestamp(sk, sockc.tsflags);
		tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);
	}
out_nopush:
	sock_zerocopy_put(uarg);
	/* 返回本次写入的数据量 */
	return copied + copied_syn;

do_error:
	skb = tcp_write_queue_tail(sk);
do_fault:
	/* 发生了错误，并且当前skb尚未包含任何数据，那么需要释放该skb */
	tcp_remove_empty_skb(sk, skb);
	/* 如果已经有数据复制到发送队列了，goto到out进行发送 */
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

![sk_buff](../../../../../images/sk_buff.png)

<p style="text-align:center">图1 sk_buff</p>



## tcp_sendmsg_locked总结如下:

1. 确定当前的MSS（PMTU的存在，该值可能是动态变化的），以及TCP可以往一个skb中填充的最大数据量size_goal（字节为单位）。这两个参数在支持TSO的情形下是不相等的，这时size_goal将会是MSS的整数倍；

2. while (msg_data_left(msg))循环负责将用户空间数据拷贝进sk buffer。

3. 接下来要寻找一个skb，分两种情况：1）如果当前发送队列中最后一个skb还有空间可以继续填充数据，那么就先往该skb中填充数据；2）如果没有现成的skb可用，那么就新分配一个。判断一个skb是否还可以容纳数据的依据就是看其当前已经保存的数据是否已经超过了size_goal；

4. 找到skb后，下一步就决定往skb的哪个区域拷贝数据，优先线性缓冲区，如果线性缓冲区没有空间了，则会往frag_list[]中放（前提是设备支持SG IO，如果设备不支持，只能重新分配skb，然后将数据拷贝到其线性缓冲区中）；

5. 拷贝过程中，如果需要会调用不同接口进行数据发送。

6. 数据发送流程如下图2:

   ![tcpsenddataflow](../../../../../images/tcpsenddataflow.jpg)

   <p style="text-align:center">图2 数据发送流程</p>

[tcp_push 和 __tcp_push_pending_frames](MPTCP-tcp_push.html)

<a href="{{ "/" | relative_url }}">{{ "返回主页" | escape }}</a>

