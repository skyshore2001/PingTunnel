# ptunnel

This is the performance tunning version of ptunnel by LIANG Jian <liangjian_2001@126.com>.

Thanks to Daniel, the original author of ptunnel who created such wonderful tool and made it works.
I got version 0.72 of the code from http://www.cs.uit.no/~daniels/PingTunnel/PingTunnel-0.72.tar.gz, 
fixed some performance issues and released new version 0.73.

Here I record some issues, my analysis, how I fix and how I wish the features in the future.

## Performance issues

The download speed through the tunnel is around 5-20KB/s.

My environment:
The ptunnel server (i.e. the proxy) is in the public net served by aliyun (Alibaba Cloud) with 5M bandwidth (i.e. the max download speed is around 500KB/s).
The ptunnel client (i.e. the forwarder) is in intranet.

Furthermore, the server uses 100% CPU during the data transferring. It affects 1 CPU core, around 20% user CPU, 80% sys CPU.

I also tested it in intranet without packet loss or speed limitation. 
The max speed the around 64KB/s.

### Problem 1: slow response of ACK packet and lots of packet loss cause low performance

The default configuration is:

- The windows size of the send queue is 64 (kPing_window_size)
- Each packet has maximum 1KB payload (kDefault_buf_size)

It replies ACK packet every 1.0 second: 
(function pt_proxy)

			//	Figure out if it's time to send an explicit acknowledgement
			if (cur->last_ack+1.0 < now && cur->send_wait_ack < kPing_window_size && cur->remote_ack_val+1 != cur->next_remote_seq) {
				...
				queue_packet(fwd_sock, ..., kProto_ack, ...);
			}

The sender sends maximum 64KB once in a batch (window size 64 * 1KB packet), then the send queue is full and wait for the ACK packet to clean the queue.
The receiver replies ACK after 1s. So the max speed is 64KB/s.

More seriously, in the public network, the receiver cannot receive 64 packets once (which means the window size is too big).
In my test environment, it can only receive 16 packets once. The other packets are all lost. 

After 1.5s (kResend_interval) the sender detects packet loss and resends each packet, one packet once:
(function pt_proxy)

			//	Check for any icmp packets requiring resend, and resend _only_ the first packet.
			if (cur->send_ring[idx].pkt && cur->send_ring[idx].last_resend+kResend_interval < now) {
				pt_log(kLog_debug, "Resending packet with seq-no %d.\n", cur->send_ring[idx].seq_no);
				...
				sendto(fwd_sock, ...);
			}

It causes the final speed is 5-20KB/s.

NOTE: It does not means it resends one packet every 1.5s. 
Actually if it detects packet loss after 1.5s, it will resend one packet every 10ms 
(suppose the send queue is full, so it cannot recv new packet from the tcp socket).

Let's have a look at the code. The select model with a 10ms timeout is used for the for-loop: (function px_proxy)

	fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	while (1) {
		// timeout = 10ms
		select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..

		// recv from tcp sock, send to icmp sock (add to send queue: cur->send_ring)
			if (FD_ISSET(cur->sock, &set) && the send queue is not full...)
				bytes		= recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
				queue_packet(fwd_sock, ...);

		// recv from icmp sock, add to recv queue: cur->recv_ring, then send to tcp
		if (FD_ISSET(fwd_sock, &set)) {
			bytes		= recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			handle_packet(buf, bytes, 0, &addr, fwd_sock);
		}

		// handle resend and ACK reply
	}

#### My solution

Reply ACK as soon as possible rather than 1s delay.

The conditions when it replies ACK are:

- Supposing the windows size is 64. When 32 packet is received, an ACK is replied, OR
- If a batch of packets are all received, an ACK is replied in the next loop with maximum delay of 10ms.

	while (1) {
		// NOTE: timeout is 10ms
		int rv = select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..
		int is_timeout = rv == 0;
		...

			//	Figure out if it's time to send an explicit acknowledgement
			if ((is_timeout || cur->xfer.icmp_in % (kPing_window_size/2)==0) && (uint16_t)(cur->remote_ack_val+1) != cur->next_remote_seq){
				queue_packet(fwd_sock, cur, kProto_ack, 0, 0);
			}
	}

I tested in the intranet. The speed is improved from ~60KB/s to >50MB/s. (window size = 64)

But it still does not work in the public network because of lots of packet loss. The speed is still around 20KB/s.
I change window size to 8, then get a wonderful result: the speed is around 500-800KB/s, which reaches the limit of the bandwidth.

Refer to the TCP implementation, it uses a small windows size (maybe 1?) initially, and doubles it if no packet loss is detected. 
Repeat it unless the limit is reached. The whole traffic control is too complex to adopt in ptunnel code.

ptunnel implements reliable connection with an simple ACK, packet resend or re-order mechanism, but not adaptive.
It's the most complex part of the ptunnel code. 
I spent around 2 days to debug issues when I changed some ACK mechanism (later I will explain), and never want to touch it again.

### Problem 2: CPU 100%

Let's see the loop again:

	fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	while (1) {
		// timeout = 10ms
		select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..

		// recv from tcp sock, send to icmp sock (add to send queue: cur->send_ring)
			if (FD_ISSET(cur->sock, &set) && the send queue is not full...)
				bytes		= recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
				queue_packet(fwd_sock, ...);

		// recv from icmp sock, add to recv queue: cur->recv_ring, then send to tcp
		if (FD_ISSET(fwd_sock, &set)) {
			bytes		= recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			handle_packet(buf, bytes, 0, &addr, fwd_sock);
		}

		// handle resend and ACK reply
	}

When the send queue is full (the other side will reply ACK every 1s), it stops receiving any packets.
Then it becomes a dead loop as select will return immediately.

My first solution is to add a sleep when the send queue is full:

			// if the send queue is full, sleep 1ms
			if (cur->send_wait_ack == kPing_window_size) {
				usleep(1000);
			}

It works. It saves CPU. The CPU cost reduces from 100% to <5% during sending big file (I tested it with a 200MB file).

But I was not satisfied with the solution as it wastes much time. 
In the test in the intranet, the max transfer speed reduces from 50MB/s to 1MB/s, although the tool is impossible used in the intranet.

The thread should be blocked in such case. But it's not easy to implement an sync mechanism 
(if the send queue is full, the thread is blocked and wait for a signal). 
In multi-thread scenario, a typical message-queue may be useful, or semaphore is also OK; but it's not multi-thread scenario.

Finally I satisfied myself with such enhanced but simple solution: 
If the send queue is full, just simply don't select on the socket, which pauses receiving and pends the thread if only 1 session.

	while (1) {
		FD_ZERO(&set);
			// if the send queue is full, pause recv
			// if (cur->sock) <-- this is the original condition
			if (cur->sock && cur->send_wait_ack < kPing_window_size) {
				FD_SET(cur->sock, &set);
				if (cur->sock >= max_sock)
					max_sock	= cur->sock+1;
			}
		...
		select(max_sock, &set, 0, 0, &timeout);
		...
	}

It works much better than the sleep version. In the intranet, the speed is ~10MB/s (window size=8) or >50MB/s with more window size.

### Problem 3: it hangs sometimes

Scenario: Both the client and server sides are re-sending old packets, no new packet can transfer.
The transfer speed reduces to 0 and never recovers.

It occurs occasionally. When I reduce the window size, the possibility increases.

In order to reproduce the bug, I set windows size to 2. 
When I transfer a big file in the public network (speed is around 200KB/s), the bug reproduces almost every time in 1 minutes.

The final state is the send queues of both the server and client are full, so one cannot send ACK to the other, 
because ACK packet also need put into the send queue.
Then they fall in the trap: resend packet, wait for ACK, and never go out. The session is in a dead lock.

It's a critical bug that would cause the tunnel suddenly 'dies'. It MUST be fixed.

NOTE: the ACK packet is also in the send queue, and waits for its ACK with resending support. 
This is also a problem that the ACK will be endless. (A sends ACK, B replies ACK, A replies ACK to B's ACK, ...)

It cost me much time to think how the dead lock forms, but finally I cannot explain exactly.

#### My solution

If the ACK packet is NOT put in the send queue, the bug would be resolved.
But there will be 2 new problems:

- the send queue cannot clean. 
 The ACK increases seq-no, but it's not in the queue, which means ACK from the other side cannot match or clean any one in the queue.
 (function handle_ack has problem)

- if the ACK packet is lost, it cannot be resent, which may causes a new hung-up.

I refactor function queue_packet that does not put ACK in the queue:

	bool is_ack = state == kProto_ack;
	...

	if (! is_ack)
		pt_pkt->seq_no			= htons(*seq);
	else
		pt_pkt->seq_no			= htons(*seq + 10000);
	...

	if (is_ack || cur->send_wait_ack >= kPing_window_size) {
		return 0;
	}

	// add to cur->send_ring
	// increase seq-no of the session

I implement ACK packet with a special seq_no (seq+10000). It's OK even when uint16_t overflow.
The packet will be handled in handle_packet by the other side.
It would not affect recv queue (ignore function handle_data), 
but just clean the send queue of the other size (used in function handle_ack, I also change the seq-no match logic).

If the ACK is lost, the other side cannot clean the queue and would resend some old packet. 
So when it detects old packet (that has been received, seq_no < the last seq_no the session handled), just replies ACK:
in function handle_data:

			if (cur->remote_ack_val >= s) { // old packet, maybe resent, so we reply ACK
				pt_log(kLog_event, "Recv old packet. Reply ACK.\n");
				queue_packet(icmp_sock, cur, kProto_ack, 0, 0);
				...
			}

In a word, the mechanism is complex. I introduce some important changes with such final result:

- DON'T put the ACK packet in the send queue
- DON'T need reply the ACK packet
- If the ACK packet is lost, the session must NOT die.

## Future work

How it works now?

ptunnel forwarder listens on TCP port, handles TCP stream and forwards it through the ICMP/DNS tunnel.

What's next?

First, it listens only on local TCP socket (like ssh's -L mode), without remote socket support (ssh's -R mode).
Can it also work like ssh tunnel? Thus we don't need ssh tunnel over ICMP Tunnel.

Second, the implementation relies on TCP socket, so just supports to tunnel TCP streams.
Can it also work like VPN to handle any traffic?

In order to ensure a reliable connection, it introduces complex mechanism with ACK/resend/re-order, simple send window.
It is NOT able to handle traffic control efficiently enough.
It would be better to re-use TCP in some way rather than implement those by itself.

It handles stream at the TCP socket level. Can it handle raw packet in the lower IP level?
I suppose an ideal way, it just listens to any IP packets on raw socket, filters and directly forwards it to the other side.

- It does not need implement reliable connection or traffic control, because TCP on top of it will ensure it. The code will be much simpler.

- It supports any IP packets like VPN. It's REAL XXX over ICMP/DNS, transparent to upper protocol, rather than handle TCP socket.

- Both the server and client should be able to modify the src/dst IP/port of the original packet, re-calc the checksum 
 before the packet is put in the tunnel and proxy-ed to the real target.

For example, on TCP level, it handles TCP stream (not packet), which calls functions like listen/accept, recv and send with 1K buffer.
But on IP level, it just calls recvfrom and sendto to handle real packet. 
The packets may be TCP SYN/ACK/RST, or UDP, ICMP, etc, but they are all transparent to the tunnel.
A buffer of 64K is OK for any IP packet.

Don't care if the big packet can transfer to the other. The IP level protocol will handle it. 
For example, even if you send a 60K packet, it will be split into fragment (MTU concept, maybe <1500 or <500) by gateways 
and re-ordered by the receiver's IP protocol stack.
Furthermore, the upper TCP can also optimize the packet size (MSS concept).

In a word, handling at IP level will much simpler, but much powerful.

## use ICMP or UDP(DNS)?

The server (proxy) MUST be started by root.
The client (forwarder) MUST use root for ICMP tunnel, but NOT requires root for DNS tunnel.

If using ICMP, The client sends ICMP request packets, which will be auto-replied with ICMP reply packets by the target computer.
It wastes bandwidth.

I try changing the packet type to ICMP reply packets. It works in the intranet, but does NOT work in the public net.
Obviously some gateway denies the ICMP reply packets without requests.

But DNS tunnel fails in my real scenario, the target intranet gateway passes some DNS packets but rejects soon,
although in my test intranet it works perfectly.

# code thumb

##  main and pt_proxy

proxy process:
main -> pt_proxy -> 
	handle_packet: handle icmp ->
		handle_data: add icmp to recv queue: cur->recv_ring
		handle_ack: remove ack-ed packet from the send queue: cur->send_ring

	queue_packet: send icmp to tcp socket, add to send queue
	send_packets: forward icmp to tcp socket, remove packet from the recv queue

forwarder process:
main -> pt_forwarder -> pt_proxy -> handle_packet,queue_packet

main:
	// if '-p' option is set:
	if (mode == kMode_forward) 
		pt_forwarder();
	else
		pt_proxy(0);
	
## pt_proxy: **the most important function**

void*		pt_proxy(void *args) {
	fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	while (1) {
		FD_ZERO(&set);
		FD_SET(fwd_sock, &set);
		foreach cur in the chain:
				FD_SET(cur->sock, &set);
		// timeout = 10ms
		select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..
		
		// handle tcp packet: send to icmp sock (add to send queue: cur->send_ring)
		foreach cur in the chain: {
			// when send queue is not full
			if (FD_ISSET(cur->sock, &set) && cur->send_wait_ack < kPing_window_size ...)
				bytes		= recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
				queue_packet(fwd_sock, ...);
			}
		}
		
		// handle icmp tunnel packet: add to recv queue: cur->recv_ring, then send to tcp
		if (FD_ISSET(fwd_sock, &set)) {
			bytes		= recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			handle_packet(buf, bytes, 0, &addr, fwd_sock);
		}
		
		foreach cur in the chain: {
			// 60s session timeout
			if (cur->last_activity + kAutomatic_close_timeout < now) {
				cur->should_remove	= 1;
				continue;
			}

			// remove packet from the recv queue and send to tcp socket
			if (cur->recv_wait_send && cur->sock)
				cur->xfer.bytes_in	+= send_packets(cur->recv_ring, &cur->recv_xfer_idx, &cur->recv_wait_send, &cur->sock);

			// 1.5s timeout: resend the first send queue packet
			if (cur->send_ring[idx].pkt && cur->send_ring[idx].last_resend+kResend_interval < now) {
				sendto(fwd_sock, (const void*)cur->send_ring[idx].pkt, cur->send_ring[idx].pkt_len, 0, (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
			}
			// send ACK
			if ((is_timeout || cur->xfer.icmp_in % (kPing_window_size/2)==0) && cur->send_wait_ack < kPing_window_size && cur->remote_ack_val+1 != cur->next_remote_seq) {
				queue_packet(fwd_sock, ...)
			}
		}
	}
}

### handle_packet: handle proxy ICMP packet. if the magic matches, then process the ptunnel packet.

		ip_pkt		= (ip_packet_t*)buf;
		pkt			= (icmp_echo_packet_t*)ip_pkt->data;
		pt_pkt		= (ping_tunnel_pkt_t*)pkt->data;

		// #define	kPing_tunnel_magic		0xD5200880
		if (ntohl(pt_pkt->magic) == kPing_tunnel_magic) {
			if ((pkt_flag == kUser_flag && type_flag == kProxy_flag) || (pkt_flag == kProxy_flag && type_flag == kUser_flag)) {
				// new session
				if (pt_pkt->state == kProxy_start) {
						create_and_insert_proxy_desc(pt_pkt->id_no, ..)
				}
				// handle session password
				else if (cur && pt_pkt->state == kProto_authenticate) {
				}
				if (cur && pt_pkt->state == kProto_close) {
					cur->should_remove	= 1;
					return;
				}
				// handle data
				if (cur && cur->sock) {
					if (pt_pkt->state == kProto_data || pt_pkt->state == kProxy_start || pt_pkt->state == kProto_ack)
						handle_data(...)
					handle_ack(...)
				}
			}
		}

### pt_forwarder:

listen to the server sock, create a thread (pt_proxy) to handle session, and add the session into 'chain' (create_and_insert_proxy_desc)
NOTE: only 1 thread to handle all the sessions (saved in the linked table 'chain').

cur->id_no is a random number to mark the session id, used to send to the right session socket.

	listen(server_sock, 10);
	while (1) {
		FD_ZERO(&set);
		FD_SET(server_sock, &set);
		if (select(server_sock+1, &set, 0, 0, &time) > 0) {
			new_sock	= accept(server_sock, (struct sockaddr*)&addr, &addr_len);
			if (num_threads <= 0) {
				pthread_create(&pid, 0, pt_proxy, 0)
			}
			rand_id	= (uint16_t)rand(); // pt_pkt->id_no -- mark the ptunnel session
			// make new session in chain
			create_and_insert_proxy_desc(rand_id, rand_id, new_sock, &addr, given_dst_ip, tcp_port, kProxy_start, kUser_flag);
		}
	}

### send and ack mechanism

pt_proxy:

	// queue packet only if the queue is not full. if full (send_wait_ack == kPing_window_size), nothing is done until all icmp ack for the queued packet is received.
			if (FD_ISSET(cur->sock, &set) && cur->send_wait_ack < kPing_window_size && (!password || cur->authenticated)) {
				queue_packet(fwd_sock, ..., &cur->send_wait_ack, ...);
			}

			...
			//	Figure out if it's time to send an explicit acknowledgement
			if (cur->last_ack+1.0 < now && cur->send_wait_ack < kPing_window_size && cur->remote_ack_val+1 != cur->next_remote_seq) {
				cur->last_ack	= now;
				queue_packet(fwd_sock, cur->pkt_type, 0, 0, cur->id_no, cur->icmp_id, &cur->my_seq, cur->send_ring, &cur->send_idx, &cur->send_wait_ack, cur->dst_ip, cur->dst_port, kProto_ack | cur->type_flag, &cur->dest_addr, cur->next_remote_seq, &cur->send_first_ack, &cur->ping_seq);
				cur->xfer.icmp_ack_out++;
			}

NOTE!!! the ack is only sent every 1s, so it blocks the sender (which is waiting for ACK to clean the ring and send another round of ring).
THIS IS THE REASON why the maximum speed is 64K (the ring size is 64, so 64 packet per second; 1K per packet) !!!

## icmp size

	kDefault_buf_size		= 1024,	/*	This constant control the maximum size of
										the payload-portion of the ICMP packets
										we send. Note that this does not include
										the IP or ICMP headers!	*/

## what does pcap do?

pcap is enabled just when '-c {device}' is used. by default it's not used.

	pt_proxy:
		if (pcap) {
			if (pcap_dispatch(pc.pcap_desc, 32, pcap_packet_handler, (u_char*)&pc.pkt_q) > 0) {
				while (pc.pkt_q.head) {
					handle_packet(cur->data, cur->bytes, 1, &addr, fwd_sock);
				}
			}
		}

	void		pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr, const u_char* pkt) {
		add packets into a queue (pqueue_t		*q = refcon, that is the user-defined arg)
	}


## when recv icmp packet, how to re-order the packet and send to the tcp socket?

	kPing_window_size		= 64,	// number of packets we can have in our send/receive ring

it send ack to every recived icmp packet. and reserve a maximum 64 (window size) loop queue to re-order the packet.
tested in intranet, nearly no packet loss or need re-order.

handle_data:
	/*	Place packet in the receive ring, in its proper place. */
	set *recv_wait_send = count of packets that is able to send to tcp (will send 

pt_proxy:
			if (cur->recv_wait_send && cur->sock)
				cur->xfer.bytes_in	+= send_packets(cur->recv_ring, &cur->recv_xfer_idx, &cur->recv_wait_send, &cur->sock);

#
vi:ft=markdown
