/*
 * Metin KAYA <kayameti@gmail.com>
 * 2010.07.13, Istanbul
 *
 * http://www.EnderUNIX.org
 */

#ifndef _FLOOD_H_
#define _FLOOD_H_


void
udp_flood(void);

void
tcp_flood(void);

void
http_get_flood(void);

void
http_post_flood(void);

void
dns_flood(void);

void
load_dns_servers(const char *path);

void
amp_dns_flood(char *qname);

void
igmp_flood(void);

void
winbomb_flood(void);

void
win98bug_flood(void);

void
bypass_synproxy(void);


#endif
