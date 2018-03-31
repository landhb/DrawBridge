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

// Crypto
#include <crypto/akcipher.h>

#define MAX_PACKET_SIZE 65535

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


// Must be packed so that the compiler doesn't byte align the structure
struct packet {
	struct ethhdr eth_h;
	struct iphdr ip_h;
	//struct icmphdr icmp_h;
	struct tcphdr tcp_h;
	char msg[MAX_PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr) - sizeof(struct ethhdr)];
} __attribute__( ( packed ) ); 


// Typdefs for cleaner code
typedef struct akcipher_request akcipher_request;
typedef struct crypto_akcipher crypto_akcipher;

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

// Crypto
akcipher_request * init_keys(crypto_akcipher **tfm);
void free_keys(crypto_akcipher *tfm, akcipher_request * req);

#endif /* _LINUX_NETFILTER_XT_KNOCK_H */