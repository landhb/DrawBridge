#include "parser.h"

/**
 *  @brief Parse the TCP Packet
 *
 *  Assumes pkt + info->offset points to the beginning of the TCP header
 *  Increments the offset by the size of the TCP header so that info->offset
 *  points to the TCP data.
 *
 *  @return 0 on success, -1 on error
 */
static ssize_t parse_tcp(void * pkt, parsed_packet * info, size_t maxsize) {
    size_t proto_h_size = 0;
    struct tcphdr * tcp_hdr = NULL;

    // Check bounds with tcp header
    if (info->offset + sizeof(struct tcphdr) > maxsize) {
        return -1;
    }

    // Read the full size of the header
    tcp_hdr = (struct tcphdr *)(pkt + info->offset);
    proto_h_size = (tcp_hdr->doff) * 4;

    // tcp spec
    if (proto_h_size < 20 || proto_h_size > 60) {
        return -1;
    }

    // Re-check the bounds with full header size
    if (info->offset + proto_h_size > maxsize) {
        return -1;
    }

    info->offset += proto_h_size; // + sizeof(struct packet);
    return 0;
}

/**
 *  @brief Parse the UDP Packet
 *
 *  Assumes pkt + info->offset points to the beginning of the UDP header
 *  Increments the offset by the size of the UDP header so that info->offset
 *  points to the UDP data.
 *
 *  @return 0 on success, -1 on error
 */
static ssize_t parse_udp(void * pkt, parsed_packet * info, size_t maxsize) {
    (void)pkt;

    // Check bounds with udp header
    if (info->offset + sizeof(struct udphdr) > maxsize) {
        return -1;
    }

    info->offset += sizeof(struct udphdr); // + sizeof(struct packet);
    return 0;
}

/**
 *  @brief Parse an IPv4 Packet
 *
 *  Extracts the Source IP and determines the offset of the inner DB packet
 *
 *  @return 0 on success, -1 on error
 */
static ssize_t parse_ipv4(void * pkt, parsed_packet * info, size_t maxsize) {
    struct iphdr *ip_h = NULL;

    // Check size before indexing into header
    if (maxsize < info->offset + sizeof(struct iphdr)) {
        return -1;
    }

    // IPv4 Header
    ip_h = (struct iphdr *)((uint8_t*)pkt + info->offset);

    // Verify protocol version
    if (ip_h->version != 4) {
        return -1;
    }

    // Verify Header size
    if (ip_h->ihl*4 < 20 || ip_h->ihl*4 > 60) {
        return -1;
    }

    // Verify Total Length
    if (ntohs(ip_h->tot_len) > maxsize) {
        return -1;
    }

    // Read the source IP
    //inet_ntoa(&info->ipstr[0], ip_h->saddr);
    info->ip.addr_4 = ip_h->saddr;
    info->version = 4;

    // Move beyond the IP header
    info->offset += ip_h->ihl*4;

    // TCP
    if ((ip_h->protocol & 0xFF) == 0x06) {
        return parse_tcp(pkt, info, maxsize);
    }
    
    // UDP
    if ((ip_h->protocol & 0xFF) == 0x11) {
        return parse_udp(pkt, info, maxsize);
    }

    // Unsupported next protocol
    return -1;
}

/**
 *  @brief Parse an IPv6 Packet
 *
 *  Extracts the Source IP and determines the offset of the inner DB packet
 *
 *  @return 0 on success, -1 on error
 */
static ssize_t parse_ipv6(void * pkt, parsed_packet * info, size_t maxsize) {
    struct ipv6hdr *ip6_h = NULL;
    
    // Check size before indexing into header
    if (maxsize < info->offset + sizeof(struct ipv6hdr)) {
        return -1;
    }

    // IPv6 header
    ip6_h = (struct ipv6hdr *)(pkt + info->offset);

    // Verify protocol version
    if (ip6_h->version != 6) {
        return -1;
    }

    // Verify Total Length
    if (ntohs(ip6_h->payload_len) + sizeof(struct ipv6hdr) > maxsize) {
        return -1;
    }

    // Read the source IP
    //inet6_ntoa(&info->ipstr[0], &(ip6_h->saddr));
    info->ip.addr_6 = ip6_h->saddr;
    info->version = 6;
    
    // Check for TCP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x06) {
        return parse_tcp(pkt, info, maxsize);
    } 
    
    // Check for UDP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x11) {
        return parse_udp(pkt, info, maxsize);
    }

    // Unsupported next protocol
    return -1;
}

void free_signature(pkey_signature *sig)
{
    if (sig->s) {
        kfree(sig->s);
    }
    if (sig->digest) {
        kfree(sig->digest);
    }
    kfree(sig);
}

// Pointer arithmatic to parse out the signature and digest
pkey_signature *parse_signature(void *pkt, uint32_t offset)
{
    // Allocate the result struct
    pkey_signature *sig = (pkey_signature *)kzalloc(sizeof(pkey_signature), GFP_KERNEL);

    if (sig == NULL) {
        return NULL;
    }

    // Get the signature size
    sig->s_size = *(uint32_t *)(pkt + offset);

    // Sanity check the sig size
    if (sig->s_size > MAX_SIG_SIZE ||
        (offset + sig->s_size + sizeof(uint32_t) > MAX_PACKET_SIZE)) {
        kfree(sig);
        return NULL;
    }

    // Copy the signature from the packet
    sig->s = (uint8_t *)kzalloc(sig->s_size, GFP_KERNEL);

    if (sig->s == NULL) {
        return NULL;
    }

    // copy the signature
    offset += sizeof(uint32_t);
    memcpy(sig->s, pkt + offset, sig->s_size);

    // Get the digest size
    offset += sig->s_size;
    sig->digest_size = *(uint32_t *)(pkt + offset);

    // Sanity check the digest size
    if (sig->digest_size > MAX_DIGEST_SIZE ||
        (offset + sig->digest_size + sizeof(uint32_t) > MAX_PACKET_SIZE)) {
        kfree(sig->s);
        kfree(sig);
        return NULL;
    }

    // Copy the digest from the packet
    sig->digest = (uint8_t *)kzalloc(sig->digest_size, GFP_KERNEL);
    offset += sizeof(uint32_t);
    memcpy(sig->digest, pkt + offset, sig->digest_size);

    return sig;
}

/**
 *  @brief Parses the received packet.
 *
 *  Extracts the Source IP and determines the offset of the inner DB packet
 *
 *  @return 0 on success, -1 on error
 */
ssize_t parse_packet(void * pkt, parsed_packet * info, size_t maxsize) {
    uint16_t ethertype = 0;
    struct ethhdr *eth_h = NULL;
    struct pvlan_ethhdr * vlan_h = NULL;

    // Check size before indexing into header
    if (maxsize < sizeof(struct ethhdr)) {
        return -1;
    }

    // Ethernet header
    eth_h = (struct ethhdr *)pkt;

    // Calculate offset start
    info->offset = sizeof(struct ethhdr);

    // First level EtherType
    ethertype = ntohs(eth_h->h_proto);

    // If the packet is VLAN tagged, move an
    // additional 4 bytes to reach the encapsulated
    // protocol.
    if (ethertype == ETH_P_8021Q) {
        info->offset = sizeof(struct pvlan_ethhdr);
        vlan_h = (struct pvlan_ethhdr *)pkt;
        ethertype = htons(vlan_h->h_vlan_encapsulated_proto);
    }

    // Check if the packet is an IPv4 packet
    if (ethertype == ETH_P_IP) {
        return parse_ipv4(pkt, info, maxsize);
    } 
    
    // Check if the packet is an IPv6 packet
    if (ethertype == ETH_P_IPV6) {
        return parse_ipv6(pkt, info, maxsize);
    } 
    
    // unsupported protocol
    return -1;
}