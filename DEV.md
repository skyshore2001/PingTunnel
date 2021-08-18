# ptunnel

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
