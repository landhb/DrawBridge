#include "drawbridge.h"

static ssize_t parse_ipv4(void * pkt, parsed_packet * info, size_t maxsize) {
    size_t proto_h_size = 0;
    struct tcphdr * tcp_hdr = NULL;
    struct iphdr *ip_h = NULL;

    // Calculate offset start
    info->offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Check size before indexing into header
    if (maxsize < info->offset) {
        return -1;
    }

    // IPv4 Header
    ip_h = (struct iphdr *)(pkt + sizeof(struct ethhdr));

    // Read the source IP
    inet_ntoa(&info->ipstr[0], ip_h->saddr);
    info->ip.addr_4 = ip_h->saddr;

    // TCP
    if ((ip_h->protocol & 0xFF) == 0x06) {
        tcp_hdr = (struct tcphdr *)(pkt + info->offset);
        proto_h_size = (tcp_hdr->doff) * 4;

        // tcp spec
        if (proto_h_size < 20 || proto_h_size > 60) {
            return -1;
        }

        info->offset += proto_h_size + sizeof(struct packet);
        return 0;
    }
    
    // UDP
    if ((ip_h->protocol & 0xFF) == 0x11) {
        proto_h_size = sizeof(struct udphdr);
        info->offset += sizeof(struct udphdr) + sizeof(struct packet);
        return 0;
    }

    // Unsupported next protocol
    return -1;
}

static ssize_t parse_ipv6(void * pkt, parsed_packet * info, size_t maxsize) {
    size_t proto_h_size = 0;
    struct tcphdr * tcp_hdr = NULL;
    struct ipv6hdr *ip6_h = NULL;
    
    // Calculate offset start
    info->offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    
    // Check size before indexing into header
    if (maxsize < info->offset) {
        return -1;
    }

    // IPv6 header
    ip6_h = (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));

    // Read the source IP
    inet6_ntoa(&info->ipstr[0], &(ip6_h->saddr));
    info->ip.addr_6 = ip6_h->saddr;
    
    // Check for TCP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x06) {
        tcp_hdr = (struct tcphdr *)(pkt + info->offset);
        proto_h_size = (tcp_hdr->doff) * 4;

        // tcp spec
        if (proto_h_size < 20 || proto_h_size > 60) {
            return -1;
        }

        info->offset += proto_h_size + sizeof(struct packet);
        return 0;
    } 
    
    // Check for UDP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x11) {
        proto_h_size = sizeof(struct udphdr);
        info->offset += sizeof(struct udphdr) + sizeof(struct packet);
        return 0;
    }

    // Unsupported next protocol
    return -1;
}

// Check IP version
ssize_t validate_packet(void * pkt, parsed_packet * info, size_t maxsize) {
    struct ethhdr *eth_h = NULL;

    // Check size before indexing into header
    if (maxsize < sizeof(struct ethhdr)) {
        return -1;
    }

    // Ethernet header
    eth_h = (struct ethhdr *)pkt;

    // Check if the packet is an IPv4 packet
    if ((eth_h->h_proto & 0xFF) == 0x08 &&
        ((eth_h->h_proto >> 8) & 0xFF) == 0x00) {
        info->version = 4;
        return parse_ipv4(pkt, info, maxsize);
    } 
    
    // Check if the packet is an IPv6 packet
    if ((eth_h->h_proto & 0xFF) == 0x86 &&
                ((eth_h->h_proto >> 8) & 0xFF) == 0xDD) {
        info->version = 6;
        return parse_ipv6(pkt, info, maxsize);
    } 
    
    // unsupported protocol
    return -1;
}