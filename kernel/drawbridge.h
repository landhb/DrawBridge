/** 
* @file drawbridge.h
* @brief Generic module header for Drawbridge
*
* @author Bradley Landherr
*
* @date 04/11/2018
*/
#ifndef _LINUX_DRAWBRIDGE_H
#define _LINUX_DRAWBRIDGE_H 1

// Protocol headers
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>

// List implementation in kernel
#include <linux/list.h>

// Crypto
#include <crypto/akcipher.h>

// Time
#include <linux/time64.h>

// Timout Configuration - default 5 min = 300000msec
#define STATE_TIMEOUT 300000

// Defaults
#define MAX_PACKET_SIZE 65535
#define MAX_SIG_SIZE 4096
#define MAX_DIGEST_SIZE 256

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

#define LOG_PRINT(fmt, args...) printk(KERN_NOTICE fmt, ##args)

/*
 * Public key cryptography signature data
 */
typedef struct pkey_signature {
    u8 *s; /* Signature */
    u32 s_size; /* Number of bytes in signature */
    u8 *digest;
    u32 digest_size; /* Number of bytes in digest */
} pkey_signature;

/*
 * Connection state for Trigger module
 */
typedef struct conntrack_state {
    // IP version type
    int type;

    // Destination port
    __be16 port;

    // Source IP
    union {
        struct in6_addr addr_6;
        __be32 addr_4;
    } src;

    // Timestamps
    unsigned long time_added;
    unsigned long time_updated;

    // List entry
    struct list_head list;
    struct rcu_head rcu;

} conntrack_state;

// Must be packed so that the compiler doesn't byte align the structure
struct packet {
    // Protocol data
    struct timespec64 timestamp;
    __be16 port;

} __attribute__((packed));

// Typdefs for cleaner code
typedef struct akcipher_request akcipher_request;
typedef struct crypto_akcipher crypto_akcipher;

// listen.c prototypes
int listen(void *data);
void inet_ntoa(char *str_ip, __be32 int_ip);

// State API
conntrack_state *init_state(void);
int state_lookup(conntrack_state *head, int type, __be32 src,
                 struct in6_addr *src_6, __be16 port);
void state_add(conntrack_state *head, int type, __be32 src,
               struct in6_addr *src_6, __be16 port);
void cleanup_states(conntrack_state *head);

// Connection Reaper API
void reap_expired_connections(unsigned long timeout);
struct timer_list *init_reaper(unsigned long timeout);
void cleanup_reaper(struct timer_list *my_timer);

// Crypto API
akcipher_request *init_keys(crypto_akcipher **tfm, void *data, int len);
void free_keys(crypto_akcipher *tfm, akcipher_request *req);
int verify_sig_rsa(akcipher_request *req, pkey_signature *sig);
void *gen_digest(void *buf, unsigned int len);


// Utils
void inet6_ntoa(char *str_ip, struct in6_addr *src_6);
void inet_ntoa(char *str_ip, __be32 int_ip);
void hexdump(unsigned char *buf, unsigned int len);

#endif /* _LINUX_DRAWBRIDGE_H */
