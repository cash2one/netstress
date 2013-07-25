/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

#ifndef _UTILS_H_
#define _UTILS_H_


#define USAGE(fmt...)	usage(__FILE__, __func__, __LINE__, fmt);
#define NS_ERR(fmt...)	ns_error(__FILE__, __func__, __LINE__, fmt);


void
ns_error(const char *file, const char *func, int line, const char *fmt, ...);

void
usage(const char *file, const char *func, int line, const char *fmt, ...);

void
arc4_set_key(unsigned char *key, unsigned int keylen);

void
arc4_crypt(void *vbuf, unsigned int len);

unsigned char
arc4_prng(void);

void
resolve(char *name, in_addr_t *ip);

void
get_sock(int *sock, int proto);

void
get_port(char *s, unsigned short *out);

unsigned short
in_cksum(u_short *addr, int len);

void
sig_handler(int signum);

void
set_dns_query_type(int *dns_type, const char *qtype);

void
prep_tcp(struct tcp_packet *packet, const char *attack_type,
		unsigned long daddr, unsigned int dport);

void
prep_udp(struct udp_packet *packet, unsigned long daddr, unsigned int dport);

void
load_country_ip(void);

void
get_local_addr(void);


#endif
