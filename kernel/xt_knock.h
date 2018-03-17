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


typedef struct conntrack_state {

	// IP version type
	int type;

	// Destination port
	__be16 port;

	// Source IP
	union {
		__be32 addr_4;
		struct in6_addr addr_6;
	} src;

	// Timestamp
	unsigned long time_added;

	// List entry
	struct list_head list;

} conntrack_state;


// listen.c prototypes
int listen(void * data);
void inet_ntoa(char * str_ip, __be32 int_ip);


// State API
conntrack_state	* init_state(void);
int state_lookup(conntrack_state * head, int type, __be32 src, struct in6_addr * src_6, __be16 port);
void state_add(conntrack_state ** head, int type, __be32 src, struct in6_addr * src_6, __be16 port);

// Connection Reaper API
void reap_expired_connections(unsigned long timeout);
struct timer_list * init_reaper(unsigned long timeout);
void cleanup_reaper(struct timer_list * my_timer);

#endif /* _LINUX_NETFILTER_XT_KNOCK_H */