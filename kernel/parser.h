#ifndef _PARSER_HEADER
#define _PARSER_HEADER 1

// Usermode definitions
#ifdef FUZZING
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    extern void kfree(void * objp);
    extern void *kzalloc(size_t size, uint32_t flags);
#else
    #include <linux/kernel.h>
    #include <linux/module.h>
    #include <net/sock.h>
#endif

// Network Header Definitions
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "vlan.h"

// Default Constants
#define MAX_PACKET_SIZE 65535
#define MAX_SIG_SIZE 4096
#define MAX_DIGEST_SIZE 256

/**
 * Public key cryptography signature data
 */
typedef struct pkey_signature {
    uint8_t *s; /* Signature */
    uint32_t s_size; /* Number of bytes in signature */
    uint8_t *digest;
    uint32_t digest_size; /* Number of bytes in digest */
} pkey_signature;

/**
 * Information parsed from untrusted packets
 */
typedef struct _parsed_packet_t {
    uint8_t version;
    __be16 port;
    size_t offset;
    uint8_t ipstr[33];
    union {
        struct in6_addr addr_6;
        __be32 addr_4;
    } ip;
    pkey_signature * sig;
} parsed_packet;

/**
 * Primary Parsing Interface that must be fuzzed
 */
ssize_t parse_packet(void * pkt, parsed_packet * info, size_t maxsize);

/**
 * Parse signature data from a packet, allocates
 */
pkey_signature * parse_signature(void *pkt, uint32_t offset);

/**
 * Cleanup the parsed signature
 */
void free_signature(pkey_signature *sig);

#endif /* _PARSER_HEADER */ 