/*	ptunnel.c
	ptunnel is licensed under the BSD license:
	
	Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
	Yellow Lemon Software. All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	- Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

	- Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

	- Neither the name of the Yellow Lemon Software nor the names of its
	  contributors may be used to endorse or promote products derived from this
	  software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
		
	Contacting the author:
	You can get in touch with me, Daniel Stoedle (that's the Norwegian letter oe,
	in case your text editor didn't realize), here: <daniels@cs.uit.no>
	
	The official ptunnel website is here:
	<http://www.cs.uit.no/~daniels/PingTunnel/>
	
	Note that the source code is best viewed with tabs set to 4 spaces.
*/

#include	"ptunnel.h"
#include	"md5.h"

#ifdef WIN32
	/* pthread porting to windows */
	typedef CRITICAL_SECTION  pthread_mutex_t;
	typedef unsigned long     pthread_t;
	#define pthread_mutex_init    InitializeCriticalSectionAndSpinCount
	#define pthread_mutex_lock    EnterCriticalSection
	#define pthread_mutex_unlock  LeaveCriticalSection

	#include <winsock2.h>
	/* Map errno (which Winsock doesn't use) to GetLastError; include the code in the strerror */
	#ifdef errno
		#undef errno
	#endif /* errno */
	#define errno GetLastError()
	/* Local error string storage */
	static char errorstr[255];
	static char * print_last_windows_error()  {
		DWORD last_error = GetLastError();
		memset(errorstr, 0, sizeof(errorstr));
		FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, last_error, 0, errorstr, sizeof(errorstr), NULL);
		snprintf(errorstr, sizeof(errorstr), "%s (%d)", errorstr, last_error);
		return errorstr;
	}
	#define strerror(x) print_last_windows_error()
#else
#ifdef HAVE_SELINUX
	#include <selinux/selinux.h>
	static char		*selinux_context = NULL;
#endif
	static uid_t		uid = 0;
	static gid_t		gid = 0;
	static char		*root_dir = NULL;
	static bool		daemonize = false;
	static FILE		*pid_file = NULL;
#endif /* WIN32 */


//	Lots of globals
pthread_mutex_t		chain_lock,				//	Lock protecting the chain of connections
  					num_threads_lock;		//	Lock protecting the num_threads variable

bool				unprivileged			= false,	//	True if user wants to run without root
					pcap					= false,	//	True if user wants packet capturing
					print_stats				= false,	//	True if user wants continuous statistics printed.
					use_syslog              = false;	//  True if user wants to log to syslog
FILE				*log_file				= 0;		//	Usually stdout, but can be altered by the user

int					tcp_port				= -1,		//	Port to send data to from the proxy
					tcp_listen_port			= -1,		//	Port the client listens on
					log_level				= kLog_event,	//	Default log level
					mode					= kMode_proxy,	//	Default mode (proxy)
					num_threads				= 0,			//	Current thread count
					max_tunnels				= kMax_tunnels,	//	Default maximum number of tunnels to support at once
					num_tunnels				= 0,			//	Current tunnel count
					use_udp					= 0;			//	True if UDP should be used for transport (proxy runs on port 53)
uint32_t			*seq_expiry_tbl			= 0,			//	Table indicating when a connection ID is allowable (used by proxy)
					given_proxy_ip			= 0,			//	Proxy's internet address
					given_dst_ip			= 0;			//	Destination client wants data forwarded to
char				*password				= 0,			//	Password (must be the same on proxy and client for authentication to succeed)
					password_digest[kMD5_digest_size],		//	MD5 digest of password
					*pcap_device			= 0;			//	Device to capture packets from

//	Some buffer constants
const int			tcp_receive_buf_len		= kDefault_buf_size,
					icmp_receive_buf_len	= kDefault_buf_size + kIP_header_size + kICMP_header_size + sizeof(ping_tunnel_pkt_t),
					pcap_buf_size			= (kDefault_buf_size + kIP_header_size + kICMP_header_size + sizeof(ping_tunnel_pkt_t)+64)*64;
char				pcap_filter_program[]	= "icmp"; // && (icmp[icmptype] = icmp-echo || icmp[icmptype] = icmp-echoreply)";

//	The chain of client/proxy connections
proxy_desc_t		*chain					= 0;
const char			*state_name[kNum_proto_types]	= { "start", "ack", "data", "close", "authenticate" };

//	Let the fun begin!
int		main(int argc, char *argv[]) {
	int				i, opt;
	md5_state_t		state;
	struct hostent	*host_ent;
#ifndef WIN32
	struct passwd	*pwnam;
	struct group	*grnam;
	pid_t			pid;
#endif
#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return -1;
	}

	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 2 ) {
		WSACleanup();
		return -1;
	}
#endif /* WIN32 */

	
	//	Seed random generator; it'll be used in combination with a timestamp
	//	when generating authentication challenges.
	srand(time(0));
	memset(password_digest, 0, kMD5_digest_size);
	
	/*	The seq_expiry_tbl is used to prevent the remote ends from prematurely
		re-using a sequence number.
	*/
	seq_expiry_tbl	= calloc(65536, sizeof(uint32_t));
	
	log_file		= stdout;
	
	//	Parse options
	opt				= kOpt_undefined;
	mode			= kMode_proxy;
	for (i=1;i<argc;i++) {
		if (strcmp(argv[i], "-p") == 0) {
			mode	= kMode_forward;
			opt		= kOpt_set_proxy_addr;
		}
		else if (strcmp(argv[i], "-x") == 0)
			opt	= kOpt_set_password;
		else if (strcmp(argv[i], "-lp") == 0)
			opt	= kOpt_set_tcp_port;
		else if (strcmp(argv[i], "-da") == 0)
			opt	= kOpt_set_tcp_dest_addr;
		else if (strcmp(argv[i], "-dp") == 0)
			opt	= kOpt_set_tcp_dest_port;
		else if (strcmp(argv[i], "-v") == 0)
			opt	= kOpt_set_verbosity;
		else if (strcmp(argv[i], "-m") == 0)
			opt = kOpt_set_max_tunnels;
		else if (strcmp(argv[i], "-u") == 0)
			unprivileged	= !unprivileged;
		else if (strcmp(argv[i], "-c") == 0)
			opt	= kOpt_set_pcap_device;
		else if (strcmp(argv[i], "-f") == 0)
			opt = kOpt_set_log_file;
		else if (strcmp(argv[i], "-s") == 0)
			print_stats		= !print_stats;
		#ifndef WIN32
		else if (strcmp(argv[i], "-syslog") == 0)
			use_syslog		= !use_syslog;
		else if (strcmp(argv[i], "-setuid") == 0)
			opt	= kOpt_set_unpriv_user;
		else if (strcmp(argv[i], "-setgid") == 0)
			opt	= kOpt_set_unpriv_group;
		else if (strcmp(argv[i], "-chroot") == 0)
			opt	= kOpt_set_root_dir;
		else if (strcmp(argv[i], "-setcon") == 0)
			opt	= kOpt_set_selinux_context;
		else if (strcmp(argv[i], "-daemon") == 0)
			opt	= kOpt_daemonize;
		#endif /* !WIN32 */
		else if (strcmp(argv[i], "-udp") == 0)
			use_udp			= 1;
		else {
			switch (opt) {
				case kOpt_set_proxy_addr:
					if (NULL == (host_ent = gethostbyname(argv[i]))) {
						pt_log(kLog_error, "Failed to look up %s as proxy address\n", argv[i]);
						return 1;
					}
					given_proxy_ip = *(uint32_t*)host_ent->h_addr_list[0];
					break;
				case kOpt_set_password:
					password				= argv[i];
					pt_log(kLog_debug, "Password set - unauthenicated connections will be refused.\n");
					//	Compute the password digest
					md5_init(&state);
					md5_append(&state, (md5_byte_t*)password, strlen(password));
					md5_finish(&state, (md5_byte_t*)password_digest);
					//	Hide the password in process listing
					memset(argv[i], ' ', strlen(argv[i]));
					break;
				case kOpt_set_tcp_port:
					tcp_listen_port			= atoi(argv[i]);
					break;
				case kOpt_set_tcp_dest_addr:
					if (NULL == (host_ent = gethostbyname(argv[i]))) {
						pt_log(kLog_error, "Failed to look up %s as destination address\n", argv[i]);
						return 1;
					}
					given_dst_ip = *(uint32_t*)host_ent->h_addr_list[0];
					break;
				case kOpt_set_tcp_dest_port:
					tcp_port				= atoi(argv[i]);
					break;
				case kOpt_set_max_tunnels:
					max_tunnels	= atoi(argv[i]);
					if (max_tunnels <= 0)
						max_tunnels	= kMax_tunnels;
					break;
				case kOpt_set_verbosity:
					log_level		= atoi(argv[i]);
					break;
				case kOpt_set_pcap_device:
					pcap_device		= argv[i];
					pcap			= 1;
					break;
				case kOpt_set_log_file:
					log_file		= fopen(argv[i], "a");
					if (!log_file) {
						log_file	= stdout;
						pt_log(kLog_error, "Failed to open log file: '%s'. Cause: %s\n", argv[i], strerror(errno));
						pt_log(kLog_error, "Reverting log to standard out.\n");
					}
					break;
				#ifndef WIN32
				case kOpt_set_unpriv_user:
					errno = 0;
					if (NULL == (pwnam = getpwnam(argv[i]))) {
						pt_log(kLog_error, "%s: %s\n", argv[i], errno ? strerror(errno) : "unknown user");
						exit(1);
					}
					uid = pwnam->pw_uid;
					if (!gid)
						gid = pwnam->pw_gid;
					break;
				case kOpt_set_unpriv_group:
					errno = 0;
					if (NULL == (grnam = getgrnam(argv[i]))) {
						pt_log(kLog_error, "%s: %s\n", argv[i], errno ? strerror(errno) : "unknown group");
						exit(1);
					}
					gid = grnam->gr_gid;
					break;
				case kOpt_set_root_dir:
					root_dir = strdup(argv[i]);
					break;
				case kOpt_set_selinux_context:
				#ifdef HAVE_SELINUX
					selinux_context = strdup(argv[i]);
				#else
					pt_log(kLog_error, "Sorry: SELinux support missing, please recompile with libselinux.\n");
					return 1;
				#endif
					break;
				case kOpt_daemonize:
					daemonize = true;
					if (NULL == (pid_file = fopen(argv[i], "w")))
						pt_log(kLog_error, "%s: %s\n", argv[i], strerror(errno));
					break;
				#endif /* !WIN32 */
				case kOpt_undefined:
					usage(argv[0]);
					return 1;
			}
			opt	= kOpt_undefined;
		}
	}
	if (opt != kOpt_undefined) {
		usage(argv[0]);
		exit(1);
	}
	if (pcap && use_udp) {
		pt_log(kLog_error, "Packet capture is not supported (or needed) when using UDP for transport.\n");
		pcap	= 0;
	}
	pt_log(kLog_info, "Starting ptunnel v %d.%.2d.\n", kMajor_version, kMinor_version);
	pt_log(kLog_info, "(c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>\n");
	pt_log(kLog_info, "Performance tunning version @2021 by LIANG Jian <liangjian_2001@126.com>\n");
	#ifdef WIN32
	pt_log(kLog_info, "Windows version by Mike Miller, <mike@mikeage.net>\n");
	#else
	pt_log(kLog_info, "Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>\n");
	#endif
	pt_log(kLog_info, "%s.\n", (mode == kMode_forward ? "Relaying packets from incoming TCP streams" : "Forwarding incoming ping packets over TCP"));
	if (use_udp)
		pt_log(kLog_info, "UDP transport enabled.\n");
	
#ifndef WIN32
  	signal(SIGPIPE, SIG_IGN);
	if (use_syslog) {
		if (log_file != stdout) {
			pt_log(kLog_error, "Logging using syslog overrides the use of a specified logfile (using -f).\n");
			fclose(log_file);
			log_file	= stdout;
		}		
		openlog("ptunnel", LOG_PID, LOG_USER);
	}
	if (NULL != root_dir) {
		pt_log(kLog_info, "Restricting file access to %s\n", root_dir);
		if (-1 == chdir(root_dir) || -1 == chroot(root_dir)) {
			pt_log(kLog_error, "%s: %s\n", root_dir, strerror(errno));
			exit(1);
		}
	}
	if (daemonize) {
		pt_log(kLog_info, "Going to the background.\n");
		if (0 < (pid = fork()))
			exit(0);
		if (0 > pid)
			pt_log(kLog_error, "fork: %s\n", strerror(errno));
		else
			if (-1 == setsid())
				pt_log(kLog_error, "setsid: %s\n", strerror(errno));
			else {
				if (0 < (pid = fork()))
					exit(0);
				if (0 > pid)
					pt_log(kLog_error, "fork: %s\n", strerror(errno));
				else {
					if (NULL != pid_file) {
						fprintf(pid_file, "%d\n", getpid());
						fclose(pid_file);
					}
					freopen("/dev/null", "r", stdin);
					freopen("/dev/null", "w", stdout);
					freopen("/dev/null", "w", stderr);
				}
			}
	}
#endif /* !WIN32 */

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return -1;
	}

	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 2 ) {
		WSACleanup();
		return -1;
	}
#endif /* WIN32 */
  	pthread_mutex_init(&chain_lock, 0);
  	pthread_mutex_init(&num_threads_lock, 0);
	
	//	Check mode, validate arguments and start either client or proxy.
	if (mode == kMode_forward) {
		if (!given_proxy_ip || !given_dst_ip || !tcp_port || !tcp_listen_port) {
			printf("One of the options are missing or invalid.\n");
			usage(argv[0]);
			return -1;
		}
		pt_forwarder();
	}
	else
		pt_proxy(0);
	
	//	Clean up
	if (log_file != stdout)
		fclose(log_file);

#ifdef WIN32
	WSACleanup();
#else
	if (NULL != root_dir)
		free(root_dir);
	#ifdef HAVE_SELINUX
	if (NULL != selinux_context)
		free(selinux_context);
	#endif
#endif /* WIN32 */

	pt_log(kLog_info, "ptunnel is exiting.\n");
	return 0;
}


void		usage(char *exec_name) {
	printf("ptunnel v %d.%.2d.\n", kMajor_version, kMinor_version);
	printf("Usage:   %s -p <addr> -lp <port> -da <dest_addr> -dp <dest_port> [-m max_tunnels] [-v verbosity] [-f logfile]\n", exec_name);
	printf("         %s [-m max_threads] [-v verbosity] [-c <device>]\n", exec_name);
	printf("     -p: Set address of peer running packet forwarder. This causes\n");
	printf("         ptunnel to operate in forwarding mode - the absence of this\n");
	printf("         option causes ptunnel to operate in proxy mode.\n");
	printf("    -lp: Set TCP listening port (only used when operating in forward mode)\n");
	printf("    -da: Set remote proxy destination address if client\n");
	printf("         Restrict to only this destination address if server\n");
	printf("    -dp: Set remote proxy destionation port if client\n");
	printf("         Restrict to only this destination port if server\n");
	printf("     -m: Set maximum number of concurrent tunnels\n");
	printf("     -v: Verbosity level (-1 to 4, where -1 is no output, and 4 is all output)\n");
	printf("     -c: Enable libpcap on the given device.\n");
	printf("     -f: Specify a file to log to, rather than printing to standard out.\n");
	printf("     -s: Client only. Enables continuous output of statistics (packet loss, etc.)\n");
	#ifndef WIN32
	printf("-daemon: Run in background, the PID will be written in the file supplied as argument\n");
	printf("-syslog: Output debug to syslog instead of standard out.\n");
	#endif /* !WIN32 */
	printf("   -udp: Toggle use of UDP instead of ICMP. Proxy will listen on port 53 (must be root).\n\n");

	printf("Security features:  [-x password] [-u] [-setuid user] [-setgid group] [-chroot dir]\n");
	printf("     -x: Set password (must be same on client and proxy)\n");
	printf("     -u: Run proxy in unprivileged mode. This causes the proxy to forward\n");
	printf("         packets using standard echo requests, instead of crafting custom echo replies.\n");
	printf("         Unprivileged mode will only work on some systems, and is in general less reliable\n");
	printf("         than running in privileged mode.\n");
	#ifndef WIN32
	printf("         Please consider combining the following three options instead:\n");
	printf("-setuid: When started in privileged mode, drop down to user's rights as soon as possible\n");
	printf("-setgid: When started in privileged mode, drop down to group's rights as soon as possible\n");
	printf("-chroot: When started in privileged mode, restrict file access to the specified directory\n");
	printf("-setcon: Set SELinux context when all there is left to do are network I/O operations\n");
	printf("         To combine with -chroot you will have to `mount --bind /proc /chrootdir/proc`\n");
	#endif /* !WIN32 */

	printf("\nStarting the proxy (needs to run as root):\n");
	printf(" [root #] %s\n", exec_name);
	printf("Starting a client (also needs root):\n");
	printf(" [root #] %s -p proxy.pingtunnel.com -lp 8000 -da login.domain.com -dp 22 -c eth0\n", exec_name);
	printf("And then using the tunnel to ssh to login.domain.com:\n");
	printf(" [user $] ssh -p 8000 localhost\n");
	printf("And that's it. Enjoy your tunnel!\n\n");
}


/*	pt_forwarder:
	Sets up a listening TCP socket, and forwards incoming connections
	over ping packets.
*/
void		pt_forwarder(void) {
	int					server_sock, new_sock, sock, yes = 1;
	fd_set				set;
	struct timeval		time;
	struct sockaddr_in	addr, dest_addr;
	socklen_t			addr_len;
	pthread_t			pid;
	uint16_t			rand_id;
	
	pt_log(kLog_debug, "Starting forwarder..\n");
	//	Open our listening socket
	sock					= socket(AF_INET, SOCK_STREAM, 0);
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &yes, sizeof(int)) == -1) {
		pt_log(kLog_error, "Failed to set SO_REUSEADDR option on listening socket: %s\n", strerror(errno));
		close(sock);
		return;
	}
	addr.sin_family			= AF_INET;
	addr.sin_port			= htons(tcp_listen_port);
	addr.sin_addr.s_addr	= INADDR_ANY;
	memset(&(addr.sin_zero), 0, 8);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr)) == -1) {
		pt_log(kLog_error, "Failed to bind listening socket: %s\n", strerror(errno));
		close(sock);
		return;
	}
	server_sock		= sock;
	//	Fill out address structure
	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	dest_addr.sin_family			= AF_INET;
	if (use_udp)
		dest_addr.sin_port			= htons(kDNS_port /* dns port.. */);
	else
		dest_addr.sin_port			= 0;
	dest_addr.sin_addr.s_addr		= given_proxy_ip;
	pt_log(kLog_verbose, "Proxy IP address: %s\n", inet_ntoa(*((struct in_addr*)&given_proxy_ip)));
	
	listen(server_sock, 10);
	while (1) {
		FD_ZERO(&set);
		FD_SET(server_sock, &set);
		time.tv_sec		= 1;
		time.tv_usec	= 0;
		if (select(server_sock+1, &set, 0, 0, &time) > 0) {
			pt_log(kLog_info, "Incoming connection.\n");
			addr_len	= sizeof(struct sockaddr_in);
			new_sock	= accept(server_sock, (struct sockaddr*)&addr, &addr_len);
			if (new_sock < 0) {
				pt_log(kLog_error, "Accepting incoming connection failed.\n");
				continue;
			}
			pthread_mutex_lock(&num_threads_lock);
			if (num_threads <= 0) {
				pt_log(kLog_event, "No running proxy thread - starting it.\n");
#ifndef WIN32
				if (pthread_create(&pid, 0, pt_proxy, 0) != 0)
#else
				if (0 == (pid = _beginthreadex(0, 0, (unsigned int (__stdcall *)(void *))pt_proxy, 0, 0, 0)))
#endif
				{
					pt_log(kLog_error, "Couldn't create thread! Dropping incoming connection.\n");
					close(new_sock);
					pthread_mutex_unlock(&num_threads_lock);
					continue;
				}
			}
			addr	= dest_addr;
			rand_id	= (uint16_t)rand();
			create_and_insert_proxy_desc(rand_id, rand_id, new_sock, &addr, given_dst_ip, tcp_port, kProxy_start, kUser_flag);
			pthread_mutex_unlock(&num_threads_lock);
		}
	}
}


int			pt_create_udp_socket(int port) {
	struct sockaddr_in	addr; 
	int					sock, yes = 1;
	
	sock = socket(AF_INET, SOCK_DGRAM, 0); 
	if (sock < 0) {
		pt_log(kLog_error, "Failed to set create UDP socket..\n");
		return 0; 
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&yes, sizeof(int)) < 0) {
		pt_log(kLog_error, "Failed to set UDP REUSEADDR socket option. (Not fatal, hopefully.)\n");
		close(sock);
		return 0;
	}
	#ifdef SO_REUSEPORT
	yes = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&yes, sizeof(int)) < 0)
		pt_log(kLog_error, "Failed to set UDP REUSEPORT socket option. (Not fatal, hopefully.)\n");
	#endif //SO_REUSEPORT
	
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family			= AF_INET;
	addr.sin_addr.s_addr	= htonl(INADDR_ANY);
	addr.sin_port			= htons(port);
	if (bind(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) < 0) {
		pt_log(kLog_error, "Failed to bind UDP socket to port %d (try running as root).\n", port);
		close(sock);
		return 0;
	}
	return sock;
}

#define	kPT_add_iphdr	0

/*	pt_proxy: This function does all the client and proxy stuff.
*/
void*		pt_proxy(void *args) {
	fd_set				set;
	struct timeval		timeout;
	int					bytes;
	struct sockaddr_in	addr;
	socklen_t			addr_len;
	int					fwd_sock	= 0,
						max_sock	= 0,
						idx;
	char				*buf;
	double				now, last_status_update = 0.0;
	proxy_desc_t		*cur, *prev, *tmp;
	pcap_info_t			pc;
	xfer_stats_t		xfer;
	
	//	Start the thread, initialize protocol and ring states.
	pt_log(kLog_debug, "Starting ping proxy..\n");
	if (use_udp) {
		pt_log(kLog_debug, "Creating UDP socket..\n");
		if (mode == kMode_proxy)
			fwd_sock	= pt_create_udp_socket(kDNS_port);
		else
			fwd_sock	= pt_create_udp_socket(0);
		if (!fwd_sock) {
			pt_log(kLog_error, "Failed to create UDP socket.\n");
			return 0;
		}
	}
	else {
		if (unprivileged) {
			pt_log(kLog_debug, "Attempting to create unprivileged ICMP datagram socket..\n");
			fwd_sock		= socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
		}
		else {
			#if kPT_add_iphdr
			int		opt = 1;
			#endif
			pt_log(kLog_debug, "Attempting to create privileged ICMP raw socket..\n");
			#if kPT_add_iphdr
			//	experimental
			fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_IP);
			printf("Set ip-hdr-inc; result = %d\n", setsockopt(fwd_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)));
			#else
			fwd_sock		= socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			#endif
		}
		if (fwd_sock < 0) {
			pt_log(kLog_error, "Couldn't create %s socket: %s\n", (unprivileged ? "unprivileged datagram" : "privileged raw"), strerror(errno));
			return 0;
		}
	}
	max_sock			= fwd_sock+1;
	if (pcap) {
		if (use_udp) {
			pt_log(kLog_error, "Packet capture is not useful with UDP [should not get here!]!\n");
			close(fwd_sock);
			return 0;
		}
		if (!unprivileged) {
			pt_log(kLog_info, "Initializing pcap.\n");
			pc.pcap_err_buf		= malloc(PCAP_ERRBUF_SIZE);
			pc.pcap_data_buf	= malloc(pcap_buf_size);
			pc.pcap_desc		= pcap_open_live(pcap_device, pcap_buf_size, 0 /* promiscous */, 50 /* ms */, pc.pcap_err_buf);
			if (pc.pcap_desc) {
				if (pcap_lookupnet(pcap_device, &pc.netp, &pc.netmask, pc.pcap_err_buf) == -1) {
					
					pt_log(kLog_error, "pcap error: %s\n", pc.pcap_err_buf);
					pcap	= 0;
				}
				pt_log(kLog_verbose, "Network: %s\n", inet_ntoa(*(struct in_addr*)&pc.netp));
				pt_log(kLog_verbose, "Netmask: %s\n", inet_ntoa(*(struct in_addr*)&pc.netmask));
				if (pcap_compile(pc.pcap_desc, &pc.fp, pcap_filter_program, 0, pc.netp) == -1) {
					pt_log(kLog_error, "Failed to compile pcap filter program.\n");
					pcap_close(pc.pcap_desc);
					pcap	= 0;
				}
				else if (pcap_setfilter(pc.pcap_desc, &pc.fp) == -1) {
					pt_log(kLog_error, "Failed to set pcap filter program.\n");
					pcap_close(pc.pcap_desc);
					pcap	= 0;
				}
			}
			else {
				pt_log(kLog_error, "pcap error: %s\n", pc.pcap_err_buf);
				pcap	= 0;
			}
			pc.pkt_q.head	= 0;
			pc.pkt_q.tail	= 0;
			pc.pkt_q.elems	= 0;
			//	Check if we have succeeded, and free stuff if not
			if (!pcap) {
				pt_log(kLog_error, "There were errors enabling pcap - pcap has been disabled.\n");
				free(pc.pcap_err_buf);
				free(pc.pcap_data_buf);
				return 0;
			}
		}
		else
			pt_log(kLog_info, "pcap disabled since we're running in unprivileged mode.\n");
	}
	
	pthread_mutex_lock(&num_threads_lock);
	num_threads++;
	pthread_mutex_unlock(&num_threads_lock);
	
	//	Allocate icmp receive buffer
	buf					= malloc(icmp_receive_buf_len);
	
	//	Start forwarding :)
	pt_log(kLog_info, "Ping proxy is listening in %s mode.\n", (unprivileged ? "unprivileged" : "privileged"));

	#ifndef WIN32
	#ifdef HAVE_SELINUX
	if (uid || gid || selinux_context)
	#else
	if (uid || gid)
	#endif
		pt_log(kLog_info, "Dropping privileges now.\n");
	if (gid && -1 == setgid(gid))
		pt_log(kLog_error, "setgid(%d): %s\n", gid, strerror(errno));
	if (uid && -1 == setuid(uid))
		pt_log(kLog_error, "setuid(%d): %s\n", uid, strerror(errno));
	#ifdef HAVE_SELINUX
	if (NULL != selinux_context && -1 == setcon(selinux_context))
		pt_log(kLog_error, "setcon(%s) failed: %s\n", selinux_context, strerror(errno));
	#endif
	#endif

	while (1) {
		FD_ZERO(&set);
		FD_SET(fwd_sock, &set);
		max_sock		= fwd_sock+1;
		pthread_mutex_lock(&chain_lock);
		for (cur=chain;cur;cur=cur->next) {
			bool authed = (!password || cur->authenticated);
			// if the send queue is full, pause recv
			if (cur->sock && cur->send_wait_ack < kPing_window_size && authed) {
				FD_SET(cur->sock, &set);
				if (cur->sock >= max_sock)
					max_sock	= cur->sock+1;
			}
		}
		pthread_mutex_unlock(&chain_lock);
		timeout.tv_sec		= 0;
		timeout.tv_usec		= 10000;
		int rv = select(max_sock, &set, 0, 0, &timeout);	//	Don't care about return val, since we need to check for new states anyway..
		int is_timeout = rv == 0;
		
		pthread_mutex_lock(&chain_lock);
		for (prev=0,cur=chain;cur;cur=tmp) {
			if (cur->should_remove) {
				pt_log(kLog_info, "\nSession statistics:\n");
				print_statistics(&cur->xfer, 0);
				pt_log(kLog_info, "\n");
				tmp	= cur->next;
				remove_proxy_desc(cur, prev);
				continue;
			}
			//	Client: If we're starting up, send a message to the remote end saying so,
			//	causing him to connect to our desired endpoint.
			if (cur->state == kProxy_start) {
				pt_log(kLog_verbose, "Sending proxy request.\n");
				queue_packet(fwd_sock, cur, cur->state, 0, 0);
				cur->state		= kProto_data;
			}
			//	Only handle traffic if there is traffic on the socket, we have
			//	room in our send window AND we either don't use a password, or
			//	have been authenticated.
			if (FD_ISSET(cur->sock, &set) && cur->send_wait_ack < kPing_window_size && (!password || cur->authenticated)) {
				bytes		= recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
				if (bytes <= 0) {
					pt_log(kLog_info, "Connection closed or lost.\n");
					tmp	= cur->next;
					send_termination_msg(cur, fwd_sock);
					pt_log(kLog_info, "Session statistics:\n");
					print_statistics(&cur->xfer, 0);
					remove_proxy_desc(cur, prev);
					//	No need to update prev
					continue;
				}
				queue_packet(fwd_sock, cur, cur->state, cur->buf, bytes);
			}
			prev	= cur;
			tmp		= cur->next;
		}
		pthread_mutex_unlock(&chain_lock);
		
		if (FD_ISSET(fwd_sock, &set)) {
			//	Handle ping traffic
			addr_len	= sizeof(struct sockaddr);
			bytes		= recvfrom(fwd_sock, buf, icmp_receive_buf_len, 0, (struct sockaddr*)&addr, &addr_len);
			if (bytes < 0) {
				pt_log(kLog_error, "Error receiving packet on ICMP socket: %s\n", strerror(errno));
				break;
			}
			handle_packet(buf, bytes, 0, &addr, fwd_sock);
		}
		
		//	Check for packets needing resend, and figure out if any connections
		//	should be closed down due to inactivity.
		pthread_mutex_lock(&chain_lock);
		now		= time_as_double();
		for (cur=chain;cur;cur=cur->next) {
			if (cur->last_activity + kAutomatic_close_timeout < now) {
				pt_log(kLog_info, "Dropping session #%d [%s:%d] due to inactivity.\n", cur->id_no, inet_ntoa(*(struct in_addr*)&cur->dst_ip), cur->dst_port);
				send_termination_msg(cur, fwd_sock);
				cur->should_remove	= 1;
				continue;
			}
			if (cur->recv_wait_send && cur->sock) {
				int rv = send_packets(cur->recv_ring, &cur->recv_xfer_idx, &cur->recv_wait_send, &cur->sock);
				if (rv < 0) {
					pt_log(kLog_error, "Dropping session #%d [%s:%d] due to the TCP sock is closed.\n", cur->id_no, inet_ntoa(*(struct in_addr*)&cur->dst_ip), cur->dst_port);
					send_termination_msg(cur, fwd_sock);
					cur->should_remove = 1;
					continue;
				}
				cur->xfer.bytes_in	+= rv;
			}
			
			//	Check for any icmp packets requiring resend, and resend _only_ the first packet.
			idx	= cur->send_first_ack;
			if (cur->send_ring[idx].pkt && cur->send_ring[idx].last_resend+kResend_interval < now) {
				pt_log(kLog_event, "Resend: [seq=%d]\n", cur->send_ring[idx].seq_no);
				cur->send_ring[idx].last_resend		= now;
				cur->send_ring[idx].pkt->seq		= htons(cur->ping_seq);
				cur->ping_seq++;
				cur->send_ring[idx].pkt->checksum	= 0;
				cur->send_ring[idx].pkt->checksum	= ~calc_checksum(cur->send_ring[idx].pkt, cur->send_ring[idx].pkt_len);
				//printf("ID: %d\n", htons(cur->send_ring[idx].pkt->identifier));
				sendto(fwd_sock, (const void*)cur->send_ring[idx].pkt, cur->send_ring[idx].pkt_len, 0, (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
				cur->xfer.icmp_resent++;
			}
			//	Figure out if it's time to send an explicit acknowledgement
			//	NOTE: force_ack is not for ack, but notify NAT device for keep-alive (required from intranet to public).
			//	why 5.0s? it MUST be less than the NAT aging time that is typically 10s for icmp request.
			bool force_ack = (cur->pkt_type == kICMP_echo_request && cur->last_ack+5.0 < now);
			bool do_ack = (is_timeout || cur->xfer.icmp_in % (kPing_window_size/2)==0) && (uint16_t)(cur->remote_ack_val+1) != cur->next_remote_seq;
			if (force_ack || do_ack){
				queue_packet(fwd_sock, cur, kProto_ack, 0, 0);
			}
		}
		pthread_mutex_unlock(&chain_lock);
		if (pcap) {
			if (pcap_dispatch(pc.pcap_desc, 32, pcap_packet_handler, (u_char*)&pc.pkt_q) > 0) {
				pqueue_elem_t	*cur;
				//pt_log(kLog_verbose, "pcap captured %d packets - handling them..\n", pc.pkt_q.elems);
				while (pc.pkt_q.head) {
					cur						= pc.pkt_q.head;
					memset(&addr, sizeof(struct sockaddr), 0);
					addr.sin_family			= AF_INET;
					addr.sin_addr.s_addr	= *(in_addr_t*)&(((ip_packet_t*)(cur->data))->src_ip);
					handle_packet(cur->data, cur->bytes, 1, &addr, fwd_sock);
					pc.pkt_q.head			= cur->next;
					free(cur);
					pc.pkt_q.elems--;
				}
				pc.pkt_q.tail		= 0;
				pc.pkt_q.head		= 0;
			}
		}
		//	Update running statistics, if requested (only once every second)
		if (print_stats && mode == kMode_forward && now > last_status_update+1) {
			pthread_mutex_lock(&chain_lock);
			memset(&xfer, 0, sizeof(xfer_stats_t));
			for (cur=chain;cur;cur=cur->next) {
				xfer.bytes_in		+= cur->xfer.bytes_in;
				xfer.bytes_out		+= cur->xfer.bytes_out;
				xfer.icmp_in		+= cur->xfer.icmp_in;
				xfer.icmp_out		+= cur->xfer.icmp_out;
				xfer.icmp_resent	+= cur->xfer.icmp_resent;
			}
			pthread_mutex_unlock(&chain_lock);
			print_statistics(&xfer, 1);
			last_status_update		= now;
		}
	}
	pt_log(kLog_debug, "Proxy exiting..\n");
	if (fwd_sock)
		close(fwd_sock);
	//	TODO: Clean up the other descs. Not really a priority since there's no
	//	real way to quit ptunnel in the first place..
	free(buf);
	pt_log(kLog_debug, "Ping proxy done\n");
	return 0;
}


/*	print_statistics: Prints transfer statistics for the given xfer block. The
	is_continuous variable controls the output mode, either printing a new line
	or overwriting the old line.
*/
void		print_statistics(xfer_stats_t *xfer, int is_continuous) {
	const double	mb		= 1024.0*1024.0;
	double			loss	= 0.0;
	FILE			*fp		= is_continuous? stdout: log_file;
	
	if (xfer->icmp_out > 0)
		loss	= (double)xfer->icmp_resent/(double)xfer->icmp_out;
	
	if (is_continuous)
		fprintf(fp, "\r");
	
	fprintf(fp, "[inf]: I/O: %6.2f/%6.2f mb ICMP I/O/R: %8d/%8d/%8d Loss: %4.1f%%",
			xfer->bytes_in/mb, xfer->bytes_out/mb, xfer->icmp_in, xfer->icmp_out, xfer->icmp_resent, loss);
	
	if (!is_continuous)
		fprintf(fp, "\n");
	fflush(fp);
}


/*	pcap_packet_handler:
	This is our callback function handling captured packets. We already know that the packets
	are ICMP echo or echo-reply messages, so all we need to do is strip off the ethernet header
	and append it to the queue descriptor (the refcon argument).
	
	Ok, the above isn't entirely correct (we can get other ICMP types as well). This function
	also has problems when it captures packets on the loopback interface. The moral of the
	story: Don't do ping forwarding over the loopback interface.
	
	Also, we currently don't support anything else than ethernet when in pcap mode. The reason
	is that I haven't read up on yet on how to remove the frame header from the packet..
*/
void		pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr, const u_char* pkt) {
	pqueue_t		*q;
	pqueue_elem_t	*elem;
	ip_packet_t		*ip;
	
	//pt_log(kLog_verbose, "Packet handler: %d =? %d\n", hdr->caplen, hdr->len);
	q		= (pqueue_t*)refcon;
	elem	= malloc(sizeof(pqueue_elem_t)+hdr->caplen-sizeof(struct ether_header));
	memcpy(elem->data, pkt+sizeof(struct ether_header), hdr->caplen-sizeof(struct ether_header));
	ip		= (ip_packet_t*)elem->data;
	//	TODO: Add fragment support
	elem->bytes	= ntohs(ip->pkt_len);
	if (elem->bytes > hdr->caplen-sizeof(struct ether_header)) {
		pt_log(kLog_error, "Received fragmented packet - unable to reconstruct!\n");
		pt_log(kLog_error, "This error usually occurs because pcap is used on devices that are not wlan or ethernet.\n");
		free(elem);
		return;
	}
	//elem->bytes	= hdr->caplen-sizeof(struct ether_header);
	elem->next	= 0;
	if (q->tail) {
		q->tail->next	= elem;
		q->tail			= elem;
	}
	else {
		q->head	= elem;
		q->tail	= elem;
	}
	q->elems++;
}



/*	handle_proxy_packet:
	Processes incoming ICMP packets for the proxy. The packet can come either from the
	packet capture lib, or from the actual socket or both.
	Input:	A buffer pointing at the start of an IP header, the buffer length and the proxy
			descriptor chain.
*/
void		handle_packet(char *buf, int bytes, int is_pcap, struct sockaddr_in *addr, int icmp_sock) {
	ip_packet_t			*ip_pkt;
	icmp_echo_packet_t	*pkt;
	ping_tunnel_pkt_t	*pt_pkt;
	proxy_desc_t		*cur;
	uint32_t			type_flag, pkt_flag, init_state;
	challenge_t			*challenge;
	struct timeval		tt;
	
	if (bytes < sizeof(icmp_echo_packet_t)+sizeof(ping_tunnel_pkt_t))
		pt_log(kLog_verbose, "Skipping this packet - too short. Expect: %d+%d = %d ; Got: %d\n", sizeof(icmp_echo_packet_t), sizeof(ping_tunnel_pkt_t), sizeof(icmp_echo_packet_t)+sizeof(ping_tunnel_pkt_t), bytes);
	else {
		if (use_udp) {
			ip_pkt		= 0;
			pkt			= (icmp_echo_packet_t*)buf;
			pt_pkt		= (ping_tunnel_pkt_t*)pkt->data;
		}
		else {
			ip_pkt		= (ip_packet_t*)buf;
			pkt			= (icmp_echo_packet_t*)ip_pkt->data;
			pt_pkt		= (ping_tunnel_pkt_t*)pkt->data;
		}
		if (ntohl(pt_pkt->magic) == kPing_tunnel_magic) {
			pt_pkt->state		= ntohl(pt_pkt->state);
			pkt->identifier		= ntohs(pkt->identifier);
			pt_pkt->id_no		= ntohs(pt_pkt->id_no);
			pt_pkt->seq_no		= ntohs(pt_pkt->seq_no);
			//	Find the relevant connection, if it exists
			pthread_mutex_lock(&chain_lock);
			for (cur=chain;cur;cur=cur->next) {
				if (cur->id_no == pt_pkt->id_no)
					break;
			}
			pthread_mutex_unlock(&chain_lock);
			
			/*	Handle the packet if it comes from "the other end." This is a bit tricky
				to get right, since we receive both our own and the other end's packets.
				Basically, a proxy will accept any packet from a user, regardless if it
				has a valid connection or not. A user will only accept the packet if there
				exists a connection to handle it.
			*/
			if (cur) {
				type_flag			= cur->type_flag;
				if (type_flag == kProxy_flag)
					cur->icmp_id	= pkt->identifier;
				
				if (!is_pcap)
					cur->xfer.icmp_in++;
			}
			else
				type_flag			= kProxy_flag;
			
			pkt_flag		= pt_pkt->state & kFlag_mask;
			pt_pkt->state	&= ~kFlag_mask;
			//	This test essentially verifies that the packet comes from someone who isn't us.
			if ((pkt_flag == kUser_flag && type_flag == kProxy_flag) || (pkt_flag == kProxy_flag && type_flag == kUser_flag)) {
				pt_log(kLog_sendrecv, "#%d Recv: [type=%s] [seq=%d] [ack=%d] [size=%d] [icmp=%s] [user=%s] [pcap=%d]\n",
								pt_pkt->id_no, state_name[pt_pkt->state & (~kFlag_mask)], pt_pkt->seq_no, ntohl(pt_pkt->ack), ntohl(pt_pkt->data_len), 
								(pkt->type == kICMP_echo_request ? "request" : "reply"), (pkt_flag == kUser_flag ? "yes" : "no"), is_pcap);
			
				pt_pkt->data_len	= ntohl(pt_pkt->data_len);
				pt_pkt->ack			= ntohl(pt_pkt->ack);
				if (pt_pkt->state == kProxy_start) {
					if (!cur && type_flag == kProxy_flag) {
						pt_log(kLog_info, "Incoming tunnel request from %s.\n", inet_ntoa(*(struct in_addr*)&addr->sin_addr));
						gettimeofday(&tt, 0);
						if (tt.tv_sec < seq_expiry_tbl[pt_pkt->id_no]) {
							pt_log(kLog_verbose, "Dropping request: ID was recently in use.\n");
							return;
						}
						pt_log(kLog_info, "Starting new session to %s:%d with ID #%d\n", inet_ntoa(*(struct in_addr*)&pt_pkt->dst_ip), ntohl(pt_pkt->dst_port), pt_pkt->id_no);
						if ((given_dst_ip && given_dst_ip != pt_pkt->dst_ip) || (-1 != tcp_port && tcp_port != ntohl(pt_pkt->dst_port))) {
							pt_log(kLog_info, "Destination administratively prohibited!\n");
							return;
						}
						if (password)
							init_state	= kProto_authenticate;
						else
							init_state	= kProto_data;
						cur			= create_and_insert_proxy_desc(pt_pkt->id_no, pkt->identifier, 0, addr, pt_pkt->dst_ip, ntohl(pt_pkt->dst_port), init_state, kProxy_flag);
						if (init_state == kProto_authenticate) {
							pt_log(kLog_debug, "Sending authentication challenge..\n");
							//	Send challenge
							cur->challenge	= generate_challenge();
							memcpy(cur->buf, cur->challenge, sizeof(challenge_t));
							queue_packet(icmp_sock, cur, kProto_authenticate, cur->buf, sizeof(challenge_t));
						}
					}
					else if (type_flag == kUser_flag) {
						pt_log(kLog_error, "Dropping proxy session request - we are not a proxy!\n");
						return;
					}
					else
						pt_log(kLog_error, "Dropping duplicate proxy session request.\n");
				}
				else if (cur && pt_pkt->state == kProto_authenticate) {
					//	Sanity check packet length, and make sure it matches what we expect
					if (pt_pkt->data_len != sizeof(challenge_t)) {
						pt_log(kLog_error, "Received challenge packet, but data length is not as expected.\n");
						pt_log(kLog_debug, "Data length: %d  Expected: %d\n", pt_pkt->data_len, sizeof(challenge_t));
						cur->should_remove				= 1;
						return;
					}
					//	Prevent packet data from being forwarded over TCP!
					pt_pkt->data_len	= 0;
					challenge			= (challenge_t*)pt_pkt->data;
					//	If client: Compute response to challenge
					if (type_flag == kUser_flag) {
						if (!password) {
							pt_log(kLog_error, "This proxy requires a password! Please supply one using the -x switch.\n");
							send_termination_msg(cur, icmp_sock);
							cur->should_remove	= 1;
							return;
						}
						pt_log(kLog_debug, "Got authentication challenge - sending response\n");
						generate_response(challenge);
						queue_packet(icmp_sock, cur, kProto_authenticate, (char*)challenge, sizeof(challenge_t));
						//	We have authenticated locally. It's up to the proxy now if it accepts our response or not..
						cur->authenticated	= 1;
						handle_data(pkt, bytes, cur, icmp_sock);
						return;
					}
					//	If proxy: Handle client's response to challenge
					else if (type_flag == kProxy_flag) {
						pt_log(kLog_debug, "Received remote challenge response.\n");
						if (validate_challenge(cur->challenge, challenge) || cur->authenticated) {
							pt_log(kLog_verbose, "Remote end authenticated successfully.\n");
							//	Authentication has succeeded, so now we can proceed to handle incoming TCP data.
							cur->authenticated	= 1;
							cur->state			= kProto_data;
							//	Insert the packet into the receive ring, to avoid confusing the	reliability mechanism.
							handle_data(pkt, bytes, cur, icmp_sock);
						}
						else {
							pt_log(kLog_info, "Remote end failed authentication.\n");
							send_termination_msg(cur, icmp_sock);
							cur->should_remove				= 1;
						}
						return;
					}
				}
				//	Handle close-messages for connections we know about
				if (cur && pt_pkt->state == kProto_close) {
					pt_log(kLog_info, "Received session close from remote peer.\n");
					cur->should_remove	= 1;
					return;
				}
				//	The proxy will ignore any other packets from the client
				//	until it has been authenticated. The packet resend mechanism
				//	insures that this isn't problematic.
				if (type_flag == kProxy_flag && password && cur && !cur->authenticated && pt_pkt->state != kProxy_start) {
					pt_log(kLog_debug, "Ignoring packet with seq-no %d - not authenticated yet.\n", pt_pkt->seq_no);
					return;
				}
				if (type_flag == kUser_flag)
					cur->authenticated	= 1;
				
				if (cur && cur->sock) {
					// NOTE: don't handle_data on kProto_ack. ACK packet use special seqno.
					if (pt_pkt->state == kProto_data || pt_pkt->state == kProxy_start)
						handle_data(pkt, bytes, cur, icmp_sock);
					handle_ack(pt_pkt, cur);
					cur->last_activity		= time_as_double();
				}
			}
			else {
				// ignore icmp packets sent by myself... why can i receive this? Reason: It's the server-side auto reply for icmp-request.
				pt_log(kLog_sendrecv, "Recv but ignored: %d [%d] bytes [user = %s]\n",
								bytes, ntohl(pt_pkt->data_len), (pkt_flag == kUser_flag ? "yes" : "no"));
			}
		}
		else
			pt_log(kLog_verbose, "Ignored incoming packet.\n");
	}
}



/*	create_and_insert_proxy_desc: Creates a new proxy descriptor, linking it into
	the descriptor chain. If the sock argument is 0, the function will establish
	a TCP connection to the ip and port given by dst_ip, dst_port.
*/
proxy_desc_t*		create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, uint32_t init_state, uint32_t type) {
	proxy_desc_t	*cur;
	
	pthread_mutex_lock(&chain_lock);
	if (num_tunnels >= max_tunnels) {
		pt_log(kLog_info, "Discarding incoming connection - too many tunnels! Maximum count is %d (adjust with the -m switch).\n", max_tunnels);
		if (sock)
			close(sock);
		pthread_mutex_unlock(&chain_lock);
		return 0;
	}
	num_tunnels++;
	pthread_mutex_unlock(&chain_lock);
	
	pt_log(kLog_debug, "Adding proxy desc to run loop. Type is %s. Will create socket: %s\n", (type == kUser_flag ? "user" : "proxy"), (sock ? "No" : "Yes"));
	cur						= calloc(1, sizeof(proxy_desc_t));
	cur->id_no				= id_no;
	cur->dest_addr			= *addr;
	cur->dst_ip				= dst_ip;
	cur->dst_port			= dst_port;
	cur->icmp_id			= icmp_id;
	if (!sock) {
		cur->sock				= socket(AF_INET, SOCK_STREAM, 0);
		memset(addr, 0, sizeof(struct sockaddr_in));
		addr->sin_port			= htons((uint16_t)dst_port);
		addr->sin_addr.s_addr	= dst_ip;
		addr->sin_family		= AF_INET;
		//	Let's just assume success, shall we?
		if (connect(cur->sock, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0) {
			pt_log(kLog_error, "Connect to %s:%d failed: %s\n", inet_ntoa(*(struct in_addr*)&addr->sin_addr.s_addr), ntohs(addr->sin_port), strerror(errno));
		}
	}
	else
		cur->sock			= sock;
	cur->state				= init_state;
	cur->type_flag			= type;
	if (cur->type_flag == kUser_flag)
		cur->pkt_type		= kICMP_echo_request;
	else
		cur->pkt_type		= (unprivileged ? kICMP_echo_request : kICMP_echo_reply);
	cur->buf				= malloc(icmp_receive_buf_len);
	cur->last_activity		= time_as_double();
	cur->authenticated		= 0;
	
	pthread_mutex_lock(&chain_lock);
	cur->next				= chain;
	chain					= cur;
	pthread_mutex_unlock(&chain_lock);
	cur->xfer.bytes_in		= 0.0;
	cur->xfer.bytes_out		= 0.0;
	return cur;
}


/*	remove_proxy_desc: Removes the given proxy desc, freeing its resources.
	Assumes that we hold the chain_lock.
*/
void		remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev) {
	int				i;
	struct timeval	tt;
	
	pt_log(kLog_debug, "Removing proxy descriptor.\n");
	//	Get a timestamp, for making an entry in the seq_expiry_tbl
	gettimeofday(&tt, 0);
	seq_expiry_tbl[cur->id_no]	= tt.tv_sec+(2*kAutomatic_close_timeout);
	
	//	Free resources associated with connection
	if (cur->buf)
		free(cur->buf);
	cur->buf	= 0;
	for (i=0;i<kPing_window_size;i++) {
		if (cur->send_ring[i].pkt)
			free(cur->send_ring[i].pkt);
		cur->send_ring[i].pkt	= 0;
		if (cur->recv_ring[i])
			free(cur->recv_ring[i]);
		cur->recv_ring[i]		= 0;
	}
	close(cur->sock);
	cur->sock	= 0;
	
	//	Keep list up-to-date
	if (prev)
		prev->next	= cur->next;
	else
		chain		= cur->next;
	if (cur->challenge)
		free(cur->challenge);
	free(cur);
	num_tunnels--;
}

#if kPT_add_iphdr
static int ip_id_counter	= 1;
#endif

/*	queue_packet:
	Creates an ICMP packet descriptor, and sends it. The packet descriptor is added
	to the given send ring, for potential resends later on.

	For ACK packet or if the queue is full, just send but not add to queue.
	If resends support is required, check if queue is full before call it (cur->send_wait_ack >= kPing_window_size).
*/
int			queue_packet(int icmp_sock, proxy_desc_t *cur, uint32_t state, char *buf, int num_bytes) {
	icmp_desc_t *ring = cur->send_ring;
	bool is_ack = state == kProto_ack;

	if (state == kProto_ack) {
		cur->xfer.icmp_ack_out++;
	}

	state |= cur->type_flag;
	
	#if kPT_add_iphdr
	ip_packet_t			*ip_pkt	= 0;
	int					pkt_len	= sizeof(ip_packet_t)+sizeof(icmp_echo_packet_t)+sizeof(ping_tunnel_pkt_t)+num_bytes,
	#else
	int					pkt_len	= sizeof(icmp_echo_packet_t)+sizeof(ping_tunnel_pkt_t)+num_bytes,
	#endif
						err		= 0;
	icmp_echo_packet_t	*pkt	= 0;
	ping_tunnel_pkt_t	*pt_pkt	= 0;
	uint16_t			ack_val	= cur->next_remote_seq-1;
	uint16_t			seq_val = !is_ack? cur->my_seq: cur->my_seq+10000;

	if (pkt_len % 2)
		pkt_len++;
	
	#if kPT_add_iphdr
	printf("add header\n");
	ip_pkt						= malloc(pkt_len);
	pkt							= (icmp_echo_packet_t*)ip_pkt->data;
	memset(ip_pkt, 0, sizeof(ip_packet_t));
	ip_pkt->vers_ihl			= 0x45;//|(pkt_len>>2);//5;//(IPVERSION << 4) | (sizeof(ip_packet_t) >> 2);
	ip_pkt->tos					= IPTOS_LOWDELAY;
	ip_pkt->pkt_len				= pkt_len;
	ip_pkt->id					= 0;	//kernel sets proper value htons(ip_id_counter);
	ip_pkt->flags_frag_offset	= 0;
	ip_pkt->ttl					= IPDEFTTL;	//	default time to live (64)
	ip_pkt->proto				= 1;	//	ICMP
	ip_pkt->checksum			= 0;	//	maybe the kernel helps us out..?
	ip_pkt->src_ip				= htonl(0x0);	//	insert source IP address here
	ip_pkt->dst_ip				= cur->dest_addr.sin_addr.s_addr;//htonl(0x7f000001);	//	localhost..
	#else
	pkt						= malloc(pkt_len);
	#endif
	
	pkt->type				= cur->pkt_type;		//	ICMP Echo request or reply
	pkt->code				= 0;		//	Must be zero (non-zero requires root)
	pkt->identifier			= htons(cur->icmp_id);
	pkt->seq				= htons(cur->ping_seq);
	pkt->checksum			= 0;
	cur->ping_seq++;
	//	Add our information
	pt_pkt					= (ping_tunnel_pkt_t*)pkt->data;
	pt_pkt->magic			= htonl(kPing_tunnel_magic);
	pt_pkt->dst_ip			= cur->dst_ip;
	pt_pkt->dst_port		= htonl(cur->dst_port);
	pt_pkt->ack				= htonl(ack_val);
	pt_pkt->data_len		= htonl(num_bytes);
	pt_pkt->state			= htonl(state);
	pt_pkt->seq_no			= htons(seq_val);
	pt_pkt->id_no			= htons(cur->id_no);
	//	Copy user data
	if (buf && num_bytes > 0)
		memcpy(pt_pkt->data, buf, num_bytes);
	#if kPT_add_iphdr
	pkt->checksum			= ~calc_checksum(pkt, pkt_len-sizeof(ip_packet_t));
	ip_pkt->checksum		= ~calc_checksum(ip_pkt, sizeof(ip_packet_t));
	#else
	pkt->checksum			= ~calc_checksum(pkt, pkt_len);
	#endif
	
	//	Send it!
	pt_log(kLog_sendrecv, "#%d Send: [type=%s] [seq=%d] [ack=%d] [size=%d] [icmp=%s] [user=%s]\n",
			cur->id_no, state_name[state & (~kFlag_mask)], seq_val, ack_val, num_bytes, (pkt->type == kICMP_echo_request ? "request" : "reply"), ((state & kUser_flag) == kUser_flag ? "yes" : "no"));
	#if kPT_add_iphdr
	err						= sendto(icmp_sock, (const void*)ip_pkt, pkt_len, 0, (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
	#else
	err						= sendto(icmp_sock, (const void*)pkt, pkt_len, 0, (struct sockaddr*)&cur->dest_addr, sizeof(struct sockaddr));
	#endif
	if (err < 0) {
		pt_log(kLog_error, "Failed to send ICMP packet: %s\n", strerror(errno));
		return -1;
	}
	else if (err != pkt_len)
		pt_log(kLog_error, "WARNING WARNING, didn't send entire packet\n");
	
	cur->remote_ack_val = ack_val;
	cur->last_ack	= time_as_double();
	cur->xfer.icmp_out	++;
	cur->xfer.bytes_out	+= num_bytes;
	if (is_ack || cur->send_wait_ack >= kPing_window_size) {
		return 0;
	}

	//	Update sequence no's and so on
	#if kPT_add_iphdr
	//	NOTE: Retry mechanism needs update for PT_add_ip_hdr
	ring[cur->send_idx].pkt			= ip_pkt;
	#else
	ring[cur->send_idx].pkt			= pkt;
	#endif
	ring[cur->send_idx].pkt_len		= pkt_len;
	ring[cur->send_idx].last_resend	= time_as_double();
	ring[cur->send_idx].seq_no		= cur->my_seq;
	ring[cur->send_idx].icmp_id		= cur->icmp_id;
	cur->my_seq++;
	if (!ring[cur->send_first_ack].pkt)
		cur->send_first_ack			= cur->send_idx;
	cur->send_wait_ack++;
	cur->send_idx++;
	if (cur->send_idx >= kPing_window_size)
		cur->send_idx	= 0;
	return 0;
}


/*	send_packets:
	Examines the passed-in ring, and forwards data in it over TCP.
*/
uint32_t	send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock) {
	forward_desc_t		*fwd_desc;
	int					bytes, total = 0;
	
	while (*await_send > 0) {
		fwd_desc	= ring[*xfer_idx];
		if (!fwd_desc)	//	We haven't got this packet yet..
			break;
		if (fwd_desc->length > 0) {
			bytes		= send(*sock, &fwd_desc->data[fwd_desc->length - fwd_desc->remaining], fwd_desc->remaining, 0);
			if (bytes < 0) {
				return -1; // TCP sock is closed.
			}
			fwd_desc->remaining	-= bytes;
			total				+= bytes;
		}
		if (!fwd_desc->remaining) {
			ring[*xfer_idx]	= 0;
			free(fwd_desc);
			(*xfer_idx)++;
			(*await_send)--;
			if (*xfer_idx >= kPing_window_size)
				*xfer_idx	= 0;
		}
		else
			break;
	}
	return total;
}


/*	handle_data:
	Utility function for handling kProto_data packets, and place the data it contains
	onto the passed-in receive ring.
*/
void		handle_data(icmp_echo_packet_t *pkt, int total_len, proxy_desc_t *cur, int icmp_sock) {

	forward_desc_t **ring = cur->recv_ring;
	ping_tunnel_pkt_t	*pt_pkt			= (ping_tunnel_pkt_t*)pkt->data;
	int					expected_len	= sizeof(ip_packet_t) + sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t); // 20+8+28
	
	/*	Place packet in the receive ring, in its proper place.
		This works as follows:
		-1. Packet == ack packet? Perform ack, and continue.
		0. seq_no < next_remote_seq, and absolute difference is bigger than w size => discard
		1. If seq_no == next_remote_seq, we have no problems; just put it in the ring.
		2. If seq_no > next_remote_seq + remaining window size, discard packet. Send resend request for missing packets.
		3. Else, put packet in the proper place in the ring (don't overwrite if one is already there), but don't increment next_remote_seq_no
		4. If packed was not discarded, process ack info in packet.
	*/
	expected_len	+= pt_pkt->data_len;
	expected_len	+= expected_len % 2;
	if (use_udp)
		expected_len	-= sizeof(ip_packet_t);
	if (total_len < expected_len) {
		pt_log(kLog_error, "Packet not completely received: %d Should be: %d. For some reason, this error is fatal.\n", total_len, expected_len);
		pt_log(kLog_debug, "Data length: %d Total length: %d\n", pt_pkt->data_len, total_len);
		//	TODO: This error isn't fatal, so it should definitely be handled in some way. We could simply discard it.
		exit(0);
	}
	if (pt_pkt->seq_no == cur->next_remote_seq) {
		//	hmm, what happens if this test is true?
		if (!ring[cur->recv_idx]) {	//  && pt_pkt->state == kProto_data
		//	pt_log(kLog_debug, "Queing data packet: %d\n", pt_pkt->seq_no);
			ring[cur->recv_idx]	= create_fwd_desc(pt_pkt->seq_no, pt_pkt->data_len, pt_pkt->data);
			cur->recv_wait_send++;
			cur->recv_idx++;
		}
		else if (ring[cur->recv_idx])
			pt_log(kLog_event, "Dup packet? seq_no=%d\n", pt_pkt->seq_no);
		
		cur->next_remote_seq++;
		if (cur->recv_idx >= kPing_window_size)
			cur->recv_idx	= 0;
		//	Check if we have already received some of the next packets
		while (ring[cur->recv_idx]) {
			if (ring[cur->recv_idx]->seq_no == cur->next_remote_seq) {
				cur->next_remote_seq++;
				cur->recv_idx++;
				if (cur->recv_idx >= kPing_window_size)
					cur->recv_idx	= 0;
			}
			else
				break;
		}
	}
	else {
		int	r, s, d, pos;
		pos	= -1;		//	If pos ends up staying -1, packet is discarded.
		r	= cur->next_remote_seq;
		s	= pt_pkt->seq_no;
		d	= s - r;
		if (d < 0) {	//	This packet _may_ be old, or seq_no may have wrapped around
			d	= (s+0xFFFF) - r;
			if (d < kPing_window_size) {
				//	Counter has wrapped, so we should add this packet to the recv ring
				pos	= (cur->recv_idx+d) % kPing_window_size;
			}
		}
		else if (d < kPing_window_size)
			pos	= (cur->recv_idx+d) % kPing_window_size;
		
		if (pos != -1) {
			if (!ring[pos]) {
				pt_log(kLog_event, "Out of order. Expected: %d  Got: %d  Inserted: %d (cur = %d)\n", cur->next_remote_seq, pt_pkt->seq_no, pos, cur->recv_idx);
				ring[pos]	= create_fwd_desc(pt_pkt->seq_no, pt_pkt->data_len, pt_pkt->data);
				cur->recv_wait_send++;
			}
		}
		else {
			if (cur->remote_ack_val >= s) { // old packet, maybe resent, so we reply ACK
				pt_log(kLog_event, "Recv old packet seq=%d. Reply ack=%d\n", pt_pkt->seq_no, cur->next_remote_seq-1);
				queue_packet(icmp_sock, cur, kProto_ack, 0, 0);
			}
		//	pt_log(kLog_debug, "Packet discarded - outside receive window.\n");
		}
	}
}


void		handle_ack(ping_tunnel_pkt_t *pt_pkt, proxy_desc_t *cur) {
	
	uint16_t seq_no = (uint16_t)pt_pkt->ack;
	// for the received ACK packet, dont send ACK again
	if (pt_pkt->state == kProto_ack && cur->remote_ack_val == seq_no-1) {
		++ cur->remote_ack_val;
	}
	if (cur->send_wait_ack == 0)
		return;

	icmp_desc_t *ring = cur->send_ring;

	int	i, can_ack = 0, count = 0;
	i	= cur->send_idx-1; // insert_idx
	if (i < 0)
		i	= kPing_window_size - 1;
	
	pt_log(kLog_debug, "Received ack-series starting at seq %d\n", seq_no);
	while (count < kPing_window_size) {
		if (!ring[i].pkt)
			break;
		// NOTE: ACK packet is not in the send queue; 
		// NOTE: the 16-bit seq_no may be wrapped: 65535,0,1,...
		// if (ring[i].seq_no == seq_no)
		int diff = (int)seq_no - (int)ring[i].seq_no;
		if (diff < -60000)
			diff += 0x10000;
		if (diff >= 0)
			can_ack	= 1;
		else if (!can_ack)
			cur->send_first_ack	= i;
		
		if (can_ack) {
			free(ring[i].pkt);
			ring[i].pkt	= 0;
			-- cur->send_wait_ack;
		}
		i--;
		if (i < 0)
			i	= kPing_window_size - 1;
		count++;
	}
}



forward_desc_t*	create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data) {
	forward_desc_t	*fwd_desc;
	fwd_desc			= malloc(sizeof(forward_desc_t)+data_len);
	fwd_desc->seq_no	= seq_no;
	fwd_desc->length	= data_len;
	fwd_desc->remaining	= data_len;
	if (data_len > 0)
		memcpy(fwd_desc->data, data, data_len);
	return fwd_desc;
}

/*
Usage: 
checksum = ~calc_checksum(data, len);

NOTE: 
- ~ is required;
- htons is NOT required (it fits for both BE and LE)
 */
uint16_t	calc_checksum(const void *data, int bytes) {
	uint32_t		sum = 0;
	const uint16_t	*data_u16 = (const uint16_t*)data;
	while (bytes > 1) {
		sum	+= *data_u16 ++;
		bytes -= 2;
	}
	if (bytes == 1) {
		char a[2] = {*(char*)data, 0};
		sum += *(uint16_t*)a;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return sum;
}

/*	generate_challenge: Generates a random challenge, incorporating the current
	local timestamp to avoid replay attacks.
*/
challenge_t*	generate_challenge(void) {
	struct timeval	tt;
	challenge_t		*c;
	int				i;
	
	c	= calloc(1, sizeof(challenge_t));
	gettimeofday(&tt, 0);
	c->sec		= tt.tv_sec;
	c->usec_rnd	= tt.tv_usec + rand();
	for (i=0;i<6;i++)
		c->random[i]	= rand();
	
	return c;
}


/*	generate_response: Generates a response to the given challenge. The response
	is generated by combining the concatenating the challenge data with the
	md5 digest of the password, and then calculating the MD5 digest of the
	entire buffer. The result is stored in the passed-in challenge, overwriting
	the challenge data.
*/
void			generate_response(challenge_t *challenge) {
	md5_byte_t	*buf;
	md5_state_t	state;
	
	buf	= malloc(sizeof(challenge_t)+kMD5_digest_size);
	memcpy(buf, challenge, sizeof(challenge_t));
	memcpy(&buf[sizeof(challenge_t)], password_digest, kMD5_digest_size);
	memset(challenge, 0, sizeof(challenge_t));
	md5_init(&state);
	md5_append(&state, buf, sizeof(challenge_t)+kMD5_digest_size);
	md5_finish(&state, (md5_byte_t*)challenge);
}


/*	validate_challenge: Checks whether a given response matches the expected
	response, returning 1 if validation succeeded, and 0 otherwise. Note that
	overwriting the local challenge with the challenge result is not a problem,
	as the data will not be used again anyway (authentication either succeeds,
	or the connection is closed down).
*/
int				validate_challenge(challenge_t *local, challenge_t *remote) {
	generate_response(local);
	if (memcmp(local, remote, sizeof(challenge_t)) == 0)
		return 1;
	return 0;
}


/*	send_termination_msg: informing remote end that
	the tunnel is being closed down.
*/
void		send_termination_msg(proxy_desc_t *cur, int icmp_sock) {
	queue_packet(icmp_sock, cur, kProto_close, 0, 0);
}


void	pt_log(int level, char *fmt, ...) {
	va_list	args;
	const char *header[]	= { "[err]: ",
								"[inf]: ",
								"[evt]: ",
								"[vbs]: ",
								"[dbg]: ",
								"[xfr]: " };
#ifndef WIN32
	int syslog_levels[] = {LOG_ERR, LOG_NOTICE, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_DEBUG};
#endif /* !WIN32 */

	if (level <= log_level) {
		va_start(args, fmt);
#ifndef WIN32
		if (use_syslog) {
			char log[255];
			int header_len;
			header_len = snprintf(log,sizeof(log),"%s",header[level]);
			vsnprintf(log+header_len,sizeof(log)-header_len,fmt,args);
			syslog(syslog_levels[level], "%s", log);
		}
		else {
#endif /* !WIN32 */
			char tmstr[40];
			time_t t = time(NULL);
			strftime(tmstr, sizeof(tmstr), "%Y-%m-%d %H:%M:%S", localtime(&t));
			fprintf(log_file, "[%s] %s", tmstr, header[level]), vfprintf(log_file, fmt, args);
		va_end(args);
#ifndef WIN32
		}
		if (log_file != stdout && !use_syslog)
#else
		if (log_file != stdout)
#endif
			fflush(log_file);
	}
}


double			time_as_double(void) {
	double			result;
	struct timeval	tt;
	
	gettimeofday(&tt, 0);
	result		= (double)tt.tv_sec + ((double)tt.tv_usec / (double)10e5);
	return result;
}
