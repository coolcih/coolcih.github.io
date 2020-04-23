---
layout: default
title:  "mptcp_connect_init hide"
date:   2020-04-09 16:42:58 +0800
categories: Network technology
---


```c
/* net/mptcp/mptcp_ctrl.c */
void mptcp_connect_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	rcu_read_lock();
	local_bh_disable();
	spin_lock(&mptcp_tk_hashlock);
	do {
		mptcp_set_key_sk(sk);/* 生成在TCP SYN中携带的本端的key(sender's key)。
		                        同时利用key生成对应的本端token。参考rfc6824 3.1节。
		                        mptcp_set_key_sk详情见下 */
	} while (mptcp_reqsk_find_tk(tp->mptcp_loc_token) ||
		 mptcp_find_token(tp->mptcp_loc_token));/* token必须是唯一的，此处查重 
		                                           token保存在两个hlist中，一个
		                                           是hlist mptcp_reqsk_tk_htb，
		                                           这是本端作为服务器，也就是接收
		                                           TCP SYN的情况。另一个是hlist 
		                                           tk_hashtable，是本端作为client
		                                           也就是发出TCP SYN的情况。因为
		                                           本端可能既是服务器也是client。
		                                           所以要find两处。 */

	__mptcp_hash_insert(tp, tp->mptcp_loc_token);/* 将token链入hlish tk_hashtable */
	spin_unlock(&mptcp_tk_hashlock);
	local_bh_enable();
	rcu_read_unlock();
    
	/* MPTCP状态变为MPTCP_MIB_MPCAPABLEACTIVE */
	MPTCP_INC_STATS(sock_net(sk), MPTCP_MIB_MPCAPABLEACTIVE); 
}
```

返回 [tcp_connect_init](MPTCP-tcp_connect_init.html)

```c
/* net\mptcp\mptcp_ctrl.c */
static void mptcp_set_key_sk(const struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isk = inet_sk(sk);

	if (sk->sk_family == AF_INET)
		tp->mptcp_loc_key = mptcp_v4_get_key(isk->inet_saddr,
						     isk->inet_daddr,
						     isk->inet_sport,
						     isk->inet_dport,
						     mptcp_seed++);/* key由源IP，目的IP，源端口，
						                      目的端口作为输入，
						                      通过siphash_2u64函数生成*/
#if IS_ENABLED(CONFIG_IPV6)
	else
		tp->mptcp_loc_key = mptcp_v6_get_key(inet6_sk(sk)->saddr.s6_addr32,
						     sk->sk_v6_daddr.s6_addr32,
						     isk->inet_sport,
						     isk->inet_dport,
						     mptcp_seed++);
#endif
	/* 通过key生成token，根据rfc6824 3.1节，the token MUST be a 
	truncated (most significant 32 bits) SHA-1 hash of the key。
	也就是先对key做sha1，然后取sha1值的高32位 */
	mptcp_key_sha1(tp->mptcp_loc_key,
		       &tp->mptcp_loc_token, NULL);
}
```

