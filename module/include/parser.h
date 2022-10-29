#ifndef _PARSER_HEADER
#define _PARSER_HEADER 1

// Usermode definitions
#ifdef FUZZING
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    extern void kfree(void * objp);
    extern void *kzalloc(size_t size, uint32_t flags);
    #include <bswaps.h>
#else
    #include <linux/inet.h>
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
#define SIG_SIZE 512
#define DIGEST_SIZE 32

// Must be packed so that the compiler doesn't byte align the structure
struct dbpacket {
    __s64 timestamp;
    __be16 port;
} __attribute__((packed));

/**
 * Public key cryptography signature data
 */
typedef struct pkey_signature {
    uint8_t s[SIG_SIZE];
    uint32_t s_size;
    uint8_t digest[DIGEST_SIZE];
    uint32_t digest_size;
} pkey_signature;

/**
 * Information parsed from untrusted packets
 */
typedef struct _parsed_packet_t {

    // IP version
    uint8_t version;

    // Destination port
    __be16 port;

    // Current offset
    size_t offset;

    // IP Address in human + binary form
    char ipstr[33];
    union {
        struct in6_addr addr_6;
        __be32 addr_4;
    } ip;

    // Drawbridge signature data
    pkey_signature sig;

    // Drabridge protocol data
    struct dbpacket metadata;
} parsed_packet;

/**
 * Primary Parsing Interface that must be fuzzed
 */
ssize_t parse_packet(parsed_packet * info, uintptr_t pkt, size_t maxsize);

// Utils
void hexdump(unsigned char *buf, unsigned int len);
void internal_inet6_ntoa(char *str_ip, size_t len, struct in6_addr *src_6);
void internal_inet_ntoa(char *str_ip, size_t len, __be32 int_ip);

#endif /* _PARSER_HEADER */
