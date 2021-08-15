#include	"ptunnel.h"

uint16_t	calc_checksum(const char *data, int bytes);

#define ntoa(n)  inet_ntoa(*(struct in_addr*)&(n))
#define aton(a) (uint32_t)inet_network(a)

typedef struct {
	uint8_t			vers_ihl,
					tos;
	uint16_t		pkt_len,
					id,
					flags_frag_offset;
	uint8_t			ttl,
					proto;	// 1 for ICMP
	uint16_t		checksum;
	uint32_t		src_ip,
					dst_ip;
	union {
		char			data[0];
		struct tcp {
			uint16_t sport;
			uint16_t dport;
			uint32_t seqno;
			uint32_t ackno;
			uint8_t a, b;
			uint16_t window;
			uint16_t checksum;
			uint16_t urgent_ptr;
		} tcp;
		struct udp {
			uint16_t sport;
			uint16_t dport;
			uint16_t len;
			uint16_t checksum;
			char			data[0];
		} udp;
		struct icmp {
			uint8_t			type,
							code;
			uint16_t		checksum,
							identifier,
							seq;
			char			data[0];
		} icmp;
	} u;
} __attribute__ ((packed)) ip_packet;

/*
typedef struct tcp_hdr
{
	uint16_t sport;
	uint16_t dport;
	uint32_t seqno;
	uint32_t ackno;
} tcp_hdr;

typedef struct udp_hdr
{
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t check;
} udp_hdr;
*/

void	pt_log(int level, char *fmt, ...) {
	va_list	args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

int main()
{
	int fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // IPPROTO_UDP
	int max_sock;
	fd_set				set;
	struct sockaddr_in	addr;
	const int icmp_receive_buf_len = 1500;
	char buf[icmp_receive_buf_len];

	while (1) {
		FD_ZERO(&set);
		FD_SET(fwd_sock, &set);
		max_sock		= fwd_sock+1;
		struct timeval		timeout;
		timeout.tv_sec		= 0;
		timeout.tv_usec		= 10000;
		select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..

		if (FD_ISSET(fwd_sock, &set)) {
			//	Handle ping traffic
			socklen_t addr_len	= sizeof(struct sockaddr);
			int bytes		= recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			if (bytes < 0) {
				pt_log(kLog_error, "Error receiving packet on ICMP socket: %s\n", strerror(errno));
				break;
			}
			handle_packet(buf, bytes, 0, &addr, fwd_sock);

		}
	}
	return 0;
}

void		handle_packet(char *buf, int bytes, int is_pcap, struct sockaddr_in *addr, int icmp_sock) {
	static int CNT = 0;
	ip_packet		*ip = (ip_packet*)buf;
	uint16_t sport = ntohs(ip->u.tcp.sport);
	uint16_t dport = ntohs(ip->u.tcp.dport);
	if (sport != 10081 && dport != 10081)
		return;
	pt_log(kLog_sendrecv, "[%d] Recv: %d, addr=%s, %s:%d->%s:%d, ip-pack-len=%d, proto=%d, seq=%d:%d \n",
			++ CNT,
			bytes, inet_ntoa(addr->sin_addr), 
			inet_ntoa(*(struct in_addr*)&ip->src_ip), sport,
			inet_ntoa(*(struct in_addr*)&ip->dst_ip), dport,
			ntohs(ip->pkt_len),
			ip->proto,
			ntohl(ip->u.tcp.seqno), ntohl(ip->u.tcp.ackno)
			);

	static int fwd_sock2		= 0;
	static struct sockaddr_in	addr2;
	if (fwd_sock2 == 0) {
		fwd_sock2 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // IPPROTO_UDP
		// fwd_sock2 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		/*
		int		opt = 1;
		setsockopt(fwd_sock2, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
		*/

		memset(&addr2, 0, sizeof(struct sockaddr_in));
		addr2.sin_port			= htons(10081);

		const char *host = "yibo2.oliveche.com";
		struct hostent	*host_ent;
		if (NULL == (host_ent = gethostbyname(host))) {
			pt_log(kLog_error, "Failed to look up %s as proxy address\n", host);
			return ;
		}

		uint32_t dst_ip = *(uint32_t*)host_ent->h_addr_list[0];
		addr2.sin_addr.s_addr	= dst_ip;
		addr2.sin_family		= AF_INET;
	}

	int tcplen = bytes - 20; // IP header size
	//ip->dst_ip = addr2.sin_addr.s_addr;
	//ip->checksum			= 0; // tcp ???
	ip->u.tcp.dport = addr2.sin_port;
	ip->u.tcp.checksum = 0;

	char buf1[1500];
	memset(buf1, 0, 1500);
	struct tcp_checksum {
		uint32_t src_ip;
		uint32_t dst_ip;
		uint8_t zero;
		uint8_t proto;
		uint16_t tcplen;
		char data[0];
	} *p = (struct tcp_checksum*)buf1;
	p->src_ip = aton("192.168.10.23");
	p->src_ip = htonl(p->src_ip);

	p->dst_ip = addr2.sin_addr.s_addr;
	p->proto = 6;
	p->tcplen = htons(tcplen);
	memcpy(p->data, &ip->u, tcplen);
	ip->u.tcp.checksum = calc_checksum(buf1, 12+tcplen);
	printf("send %s\n", ntoa(p->src_ip));
	printf("send %s\n", ntoa(p->dst_ip));

	int n = sendto(fwd_sock2, &ip->u, tcplen, 0, (struct sockaddr*)&addr2, sizeof(struct sockaddr));

	/*
	int udplen = 12;
	ip->u.udp.len = htons(udplen);
	ip->u.udp.dport = addr2.sin_port;
	ip->u.udp.checksum = 0;
//	ip->u.udp.checksum = htons(calc_checksum((uint16_t*)ip->u.udp.data, 4)); // WRONG!
	int n = sendto(fwd_sock2, &ip->u, udplen, 0, (struct sockaddr*)&addr2, sizeof(struct sockaddr));
	*/

	pt_log(kLog_info, "sock %d send %d bytes to %s:%d. error=%d: %s\n", fwd_sock2, n, 
			inet_ntoa(addr2.sin_addr), ntohs(ip->u.tcp.dport),
			errno, strerror(errno));
}

uint16_t	calc_checksum(const char *data, int bytes) {
	uint32_t		sum = 0;
	while (bytes > 1) {
		sum	+= *(uint16_t*)data;
		bytes -= 2;
		data += 2;
	}
	if (bytes == 1) {
		char a[2] = {*data, 0};
		sum += *(uint16_t*)a;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return ~sum;
}
