---
layout: default
title:  "tcp_connect hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/ipv4/tcp_output.c */
/* Build a SYN and send it off. */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */
    
	/* Do all connect socket setups that can be done AF(Address Family) independent.
	   在Unix/Linux系统中，在不同的版本中AF_INET和PF_INET有微小差别.对于BSD,是AF,
	   对于POSIX是PF。AF = Address Family /  PF = Protocol Family
	   理论上建立socket时是指定协议，应该用PF_xxxx，设置地址时应该用AF_xxxx。当然AF_INET
	   和PF_INET的值是相同的，混用也不会有太大的问题。在函数socketpair与socket的domain参
	   数中有AF_UNIX,AF_LOCAL,AF_INET,PF_UNIX,PF_LOCAL,PF_INET。这几个参数有
	   AF_UNIX=AF_LOCAL, PF_UNIX=PF_LOCAL, AF_LOCAL=PF_LOCAL, AF_INET=PF_INET。
	   建议:对于socketpair与socket的domain参数,使用PF_LOCAL系列,而在初始化套接口地址结
	   构时,则使用AF_LOCAL. 例如:
	   z = socket(PF_LOCAL, SOCK_STREAM, 0);
	   adr_unix.sin_family = AF_LOCAL; */
	/* 此函数设置TCP初始的MTU，拥塞控制算法(ca - congestion algrithm)，最大的广播窗口，
	   自己的MSS，猜测对端的MSS，自己的接收窗口大小，基本上不依赖它处就可以初始化的参数都在
	   这个函数做。对于MPTCP，不依赖于它处的参数也在这个函数中进行初始化，参数初始化时分两种
	   情况，1. 主sock，也就是meta sock。2. 新subflow对应的sock。*/
	/* 详情点击下方链接 */
	tcp_connect_init(sk);

	if (unlikely(tp->repair)) {
		tcp_finish_connect(sk, NULL);
		return 0;
	}

	buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;
	/* tcp_connect负责发送TCP SYN。所以必须让后面的发送函数tcp_transmit_skb知道如何
	   生成TCP头部信息，此处就是让tcp_transmit_skb知道生成一个TCP SYN，方式就是用此函
	   数设置TCP_SKB_CB(skb)->tcp_flags为TCPHDR_SYN */
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
	tcp_mstamp_refresh(tp);
	tp->retrans_stamp = tcp_time_stamp(tp);
	tcp_connect_queue_skb(sk, buff);
	tcp_ecn_send_syn(sk, buff);/* ECN-Explicit Congestion Notification显式拥塞控制。fc3168。 
	                              ECN允许拥塞控制的端对端通知而避免丢包。ECN为一项可选功能，
	                              如果底层网络设施支持，则可能被启用ECN的两个端点使用。通常
	                              来说，TCP/IP网络通过丢弃数据包来表明信道阻塞。在ECN成功协
	                              商的情况下，ECN感知路由器可以在IP头中设置一个标记来代替丢
	                              弃数据包，以标明阻塞即将发生。数据包的接收端回应发送端的表
	                              示，降低其传输速率，就如同在往常中检测到包丢失那样。此函数
	                              这里只是根据sysctl_tcp_ecn判断是否使用ecn进而设置标志位
	                              tp->ecn_flags，并没有生成真正的包头信息。 */
	tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);

	/* Send off SYN; include data in Fast Open. */
	/* 调用tcp_transmit_skb函数进行TCP报文发送，它会根据相关flag生成相应的TCP头信息例如
	   TCP SYN以及TCP option。很显然MPTCP相关的option也由此函数过程生成。详情点击下方链接 */
	/* 如果是tcp fast open场景(RFC7431)，会先调用tcp_send_syn_data，然后由其再调用	
	tcp_transmit_skb，tcp_send_syn_data主要作用是获取cached的cookie来为后续生成的SYN报文
	做准备，例如，fast open支持使用IANA定义的option kind 34或者使用experiment kink 254进行
	信息交换，至于使用哪一种方式，取决于cookie cache建立之前对端(发SYN)和本端(收SYN)的沟通使用
	的是何种方式，tcp_send_syn_data->tcp_fastopen_cookie_check会将方式从cache读出，以便
	本端发SYN时使用。关于tcp_send_syn_data详情点击下方链接 */
	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	buff = tcp_send_head(sk); /* TODO */
	if (unlikely(buff)) {
		tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	/* TCP状态变为TCP_MIB_ACTIVEOPENS */
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
```

[tcp_connect_init](MPTCP-tcp_connect_init.html)

[tcp_transmit_skb](MPTCP-tcp_transmit_skb.html)

[tcp_send_syn_data](MPTCP-tcp_send_syn_data.html)

返回 [tcp_v4_connect](MPTCP-code-study.html)