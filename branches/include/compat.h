/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

#ifndef _COMPAT_H_
#define _COMPAT_H_


#ifdef HOLYBSD
#define IPHDR		struct ip
#define SADDR		ip_src.s_addr
#define DADDR		ip_dst.s_addr
#define VER			ip_v
#define PROTO		ip_p
#define HL			ip_hl
#define TTL			ip_ttl
#define LEN			ip_len
#define IPSUM		ip_sum
#define IPID		ip_id
#define IPOFF		ip_off
#define UHSPORT		uh_sport
#define UHDPORT		uh_dport
#define UHLEN		uh_ulen
#define UHSUM		uh_sum
#define ICMPTYPE	icmp_type
#define ICMPCODE	icmp_code
#define ICMPSUM		icmp_cksum
#define TCPSPORT	th_sport
#define TCPDPORT	th_dport
#define TCPSUM		th_sum
#define TCPSEQ		th_seq
#define TCPACK		th_ack
#define TCPOFF		th_off
#define TCPWIN		th_win
#else
#define IPHDR		struct iphdr
#define SADDR		saddr
#define DADDR		daddr
#define VER			version
#define PROTO		protocol
#define HL			ihl
#define TTL			ttl
#define LEN			tot_len
#define IPSUM		check
#define IPID		id
#define IPOFF		frag_off
#define UHSPORT		source
#define UHDPORT		dest
#define UHLEN		len
#define UHSUM		check
#define ICMPTYPE	type
#define ICMPCODE	code
#define ICMPSUM		checksum
#define TCPSPORT	source
#define TCPDPORT	dest
#define TCPSUM		check
#define TCPSEQ		seq
#define TCPACK		ack_seq
#define TCPOFF		doff
#define TCPWIN		window
#endif


#endif
