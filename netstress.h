/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

#ifndef _NETSTRESS_H_
#define _NETSTRESS_H_

#include <netinet/ip.h>
#include <netinet/udp.h>


#define  DNS_TYPE_A			htons(1)
#define  DNS_TYPE_NS		htons(2)
#define  DNS_TYPE_CNAME		htons(5)
#define  DNS_TYPE_SOA		htons(6)
#define  DNS_TYPE_WKS		htons(11)
#define  DNS_TYPE_PTR		htons(12)
#define  DNS_TYPE_HINFO		htons(13)
#define  DNS_TYPE_MINFO		htons(14)
#define  DNS_TYPE_MX		htons(15)
#define  DNS_TYPE_TXT		htons(16)

#define  DNS_CLASS_IN		htons(1)
#define  DNSHDRSIZ			12
#define  IPHDRSIZ			(sizeof(IPHDR))
#define  TCPHDRSIZ			(sizeof(struct tcphdr))
#define  UDPHDRSIZ			(sizeof(struct udphdr))
#define  IGMPHDRSIZ			(IPHDRSIZ + sizeof(struct igmp))
#define  IGMPBIGSIZ			1500


struct tcp_packet {
	unsigned char	verihl;
	unsigned char	tos;
	unsigned short	len;
	unsigned short	id;
	unsigned short	flg_ofs;
	unsigned char	ttl;
	unsigned char	proto;
	unsigned short	ipsum;
	unsigned long	src;
	unsigned long	dst;
	unsigned short	sport;
	unsigned short	dport;
	unsigned long	seq;
	unsigned long	ack_seq;
	unsigned char	offset;
	unsigned char	flags;
	unsigned short	win;
	unsigned short	tcpsum;
	unsigned short	urgptr;
	char			opt[20];
};

struct udp_pseudo {
	unsigned int	src_addr;
	unsigned int	dst_addr;
	unsigned char	dummy;
	unsigned char	proto;
	unsigned short	length;
};

struct help_checksum {
	struct udp_pseudo	pshd;
	struct udphdr		udphd;
};

struct arc4_ctx {
	unsigned char S[256];
	unsigned char x, y;
};

struct udp_packet {
	IPHDR			ip;
	struct udphdr	udp;
};

struct dnshdr {
	unsigned short int	id;
	unsigned char		rd:1;
	unsigned char		tc:1;
	unsigned char		aa:1;
	unsigned char		opcode:4;
	unsigned char		qr:1;
	unsigned char		rcode:4;
	unsigned char		unused:2;
	unsigned char		pr:1;
	unsigned char		ra:1;
	unsigned short int	que_num;
	unsigned short int	rep_num;
	unsigned short int	num_rr;
	unsigned short int	num_rrsup;
};

struct country_subnet {
	unsigned long	subnet;
	unsigned long	maxip;
};


#endif
