#include	"ptunnel.h"

void	pt_log(int level, char *fmt, ...) {
	va_list	args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

int main()
{
	int fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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
	pt_log(kLog_sendrecv, "Recv: %d, addr=%s \n", bytes, inet_ntoa(addr->sin_addr));
}
