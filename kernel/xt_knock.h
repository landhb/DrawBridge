#ifndef _LINUX_NETFILTER_XT_KNOCK_H
#define _LINUX_NETFILTER_XT_KNOCK_H 1


// Protocol headers
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// List implementation in kernel
#include <linux/list.h>



/* IPv6 Address struct 
struct in6_addr
{
	union 
	{
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
}; */


typedef struct ip4_conntrack_state {
	__be16 port;
	__be32 src;
	unsigned long time_added;
	struct list_head list;
} ip4_conntrack_state;


typedef	struct ip6_conntrack_state {
	__be16 port;
	struct in6_addr src;
	unsigned long time_added;
	struct list_head list;
} ip6_conntrack_state;


// listen.c prototypes
int listen(void * data);
void inet_ntoa(char * str_ip, __be32 int_ip);


// State API
//void state_sync_init(void);
ip4_conntrack_state	* init_ip4_state(void);
ip6_conntrack_state	* init_ip6_state(void);
int ip4_state_lookup(ip4_conntrack_state * head, __be32 src, __be16 port);
void ip4_state_add(ip4_conntrack_state ** head, __be32 src, __be16 port);

#endif /* _LINUX_NETFILTER_XT_KNOCK_H */