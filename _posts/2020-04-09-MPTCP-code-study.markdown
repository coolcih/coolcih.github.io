---
layout: post
title:  "MPTCP代码分析"
date:   2020-04-09 12:06:58 +0800
categories: Network technology
---



<details>
<summary open>
//用户空间调用connect函数后，一路触发此函数调用。此函数会最后触发TCP SYN包发出。
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)</summary><blockquote>
<pre><code>
{
	...//TODO添加必要函数注释
	<details>
	<summary>  /* Build a SYN and send it off. */
	err = tcp_connect(sk);</summary>
	<blockquote><pre><code>
	{
		struct tcp_sock *tp = tcp_sk(sk);
		struct sk_buff *buff;
		int err;<br>		
		tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);<br>
		if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
			return -EHOSTUNREACH; /* Routing failure or similar. */<br>
		tcp_connect_init(sk);<br>
		if (unlikely(tp->repair)) {
			tcp_finish_connect(sk, NULL);
			return 0;
		}<br>
		buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
		if (unlikely(!buff))
			return -ENOBUFS;<br>
		tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
		tcp_mstamp_refresh(tp);
		tp->retrans_stamp = tcp_time_stamp(tp);
		tcp_connect_queue_skb(sk, buff);
		tcp_ecn_send_syn(sk, buff);
		tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);<br>
		/* Send off SYN; include data in Fast Open. */
		err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	 	     tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
		if (err == -ECONNREFUSED)
			return err;<br>
        /* We change tp->snd_nxt after the tcp_transmit_skb() call
         * in order to make this packet get counted in tcpOutSegs.
         */
        tp->snd_nxt = tp->write_seq;
        tp->pushed_seq = tp->write_seq;
        buff = tcp_send_head(sk);
        if (unlikely(buff)) {
            tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
            tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
        }
        TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);<br>
        /* Timer for repeating the SYN until an answer. */
        inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
                      inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
        return 0;
    }</code></pre></blockquote>
	</details>
}
</code></pre>
</blockquote>
</details>







```c
/* tcp_ipv4.c*/
//用户空间调用connect函数后，会触发此函数调用。此函数会最后触发TCP SYN包发出。
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	...//TODO添加必要函数注释
        
    /*TODO*/
	rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
			      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			      IPPROTO_TCP,
			      orig_sport, orig_dport, sk);

	...//TODO添加必要函数注释
        
	/* Build a SYN and send it off. */
	err = tcp_connect(sk);
}
```

[ip_route_connect](MPTCP-ip_route_connect.html)

[tcp_connect](MPTCP-tcp_connect.html)

You’ll find this post in your `_posts` directory. Go ahead and edit it and re-build the site to see your changes. You can rebuild the site in many different ways, but the most common way is to run `jekyll serve`, which launches a web server and auto-regenerates your site when a file is updated.

Jekyll requires blog post files to be named according to the following format:

`YEAR-MONTH-DAY-title.MARKUP`

Where `YEAR` is a four-digit number, `MONTH` and `DAY` are both two-digit numbers, and `MARKUP` is the file extension representing the format used in the file. After that, include the necessary front matter. Take a look at the source for this post to get an idea about how it works.

Jekyll also offers powerful support for code snippets:

{% highlight ruby %}
def print_hi(name)
  puts "Hi, #{name}"
end
print_hi('Tom')
#=> prints 'Hi, Tom' to STDOUT.
{% endhighlight %}

Check out the [Jekyll docs][jekyll-docs] for more info on how to get the most out of Jekyll. File all bugs/feature requests at [Jekyll’s GitHub repo][jekyll-gh]. If you have questions, you can ask them on [Jekyll Talk][jekyll-talk].

[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/
[tcp_connect]: https://www.baidu.com

```

```