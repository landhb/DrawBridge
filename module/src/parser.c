/** 
* @file parser.c
* @brief Drawbridge - Raw Packet Parser 
*
* Is used after the BPF filter to extract necessary data and later
* validate if a packet properly authenticates.
*
* @author Bradley Landherr
*
* @date 04/11/2018, modified 04/04/2022
*/
#include "parser.h"

/**
 *  @brief Parse the Signature, Digest, and Drawbridge Protocol data
 *
 *  Assumes pkt + info->offset points to the beginning of the Layer 3 payload
 *  Increments the offset by the size of the data so that info->offset
 *  points to the data following all data.
 * 
 *  maxsize must contain the size of the pkt allocation so no out-of-bounds
 *  reads occur.
 * 
 *  @return 0 on success, -1 on error
 */
ssize_t parse_payload(parsed_packet * info, void *pkt, size_t maxsize) {

    // Check if there is room for the metadata
    if (info->offset + sizeof(struct dbpacket) > maxsize) {
        return -1;
    }

    // Parse the 64bit timestamp
    info->metadata.timestamp = (__s64)be64_to_cpup((__be64 *)(pkt + info->offset));
    info->offset += sizeof(__be64);

    // Parse the 16bit port to unlock
    info->metadata.port = be16_to_cpup((__be16 *)(pkt + info->offset));
    info->offset += sizeof(__be16);

    // Check if there is room for the size + signature
    if (info->offset + SIG_SIZE + sizeof(__be32) > maxsize) {
        return -1;
    }

    // Get the signature size
    info->sig.s_size = be32_to_cpup((__be32 *)(pkt + info->offset));
    info->offset += sizeof(__be32);

    // Sanity check the sig size
    if (info->sig.s_size != SIG_SIZE) {
        return -1;
    }

    // copy the signature from the packet
    memcpy(&info->sig.s[0], pkt + info->offset, SIG_SIZE);
    info->offset += SIG_SIZE;

    // Check if there is room for the size + digest
    if (info->offset + DIGEST_SIZE + sizeof(__be32) > maxsize) {
        return -1;
    }

    // Get the digest size
    info->sig.digest_size = be32_to_cpup((__be32 *)(pkt + info->offset));
    info->offset += sizeof(__be32);

    // Sanity check the digest size
    if (info->sig.digest_size != DIGEST_SIZE) {
        return -1;
    }

    // Copy the digest from the packet
    memcpy(&info->sig.digest[0], pkt + info->offset, DIGEST_SIZE);
    info->offset += DIGEST_SIZE;
    return 0;
}


/**
 *  @brief Parse the TCP Packet
 *
 *  Assumes pkt + info->offset points to the beginning of the TCP header
 *  Increments the offset by the size of the TCP header so that info->offset
 *  points to the TCP data.
 *
 *  @return 0 on success, -1 on error
 */
static ssize_t parse_tcp(void * pkt, parsed_packet * info, size_t ip_payload_len, size_t maxsize) {
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
    if (info->offset + proto_h_size >= maxsize) {
        return -1;
    }

    // Check that there is enough room in the payload
    if (ip_payload_len - proto_h_size < sizeof(struct pkey_signature) + sizeof(struct dbpacket)) {
        return -1;
    }

    // Advance offset to payload
    info->offset += proto_h_size;
    return parse_payload(info, pkt, maxsize);
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
    struct udphdr * udp_hdr = NULL;

    // Check bounds with udp header
    if (info->offset + sizeof(struct udphdr) > maxsize) {
        return -1;
    }

    // Verify total length
    udp_hdr = (struct udphdr *)(pkt + info->offset);
    if (udp_hdr->len + info->offset >= maxsize) {
        return -1;
    }

    // Check that there is enough room in the payload
    if (udp_hdr->len - sizeof(struct udphdr) < sizeof(struct pkey_signature) + sizeof(struct dbpacket)) {
        return -1;
    }

    // Advance offset to payload
    info->offset += sizeof(struct udphdr);
    return parse_payload(info, pkt, maxsize);
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

    // Verify Total Length not too large
    if (ntohs(ip_h->tot_len) + info->offset > maxsize) {
        return -1;
    }

    // Verify Total Length not too small
    if (ntohs(ip_h->tot_len) < ip_h->ihl*4) {
        return -1;
    }

    // Read the source IP
    internal_inet_ntoa(&info->ipstr[0], sizeof(info->ipstr), ip_h->saddr);
    info->ip.addr_4 = ip_h->saddr;
    info->version = 4;

    // Advance the offset to the encapsulated payload
    info->offset += ip_h->ihl*4;

    // TCP
    if ((ip_h->protocol & 0xFF) == 0x06) {
        return parse_tcp(pkt, info, ntohs(ip_h->tot_len) - ip_h->ihl*4, maxsize);
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

    // Verify Total Length is not too large
    if (ntohs(ip6_h->payload_len) + sizeof(struct ipv6hdr) + info->offset > maxsize) {
        return -1;
    }

    // Read the source IP
    internal_inet6_ntoa(&info->ipstr[0], sizeof(info->ipstr), &(ip6_h->saddr));
    info->ip.addr_6 = ip6_h->saddr;
    info->version = 6;

    // Advance the offset to the encapsulated payload
    info->offset += sizeof(struct ipv6hdr);
    
    // Check for TCP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x06) {
        return parse_tcp(pkt, info, ntohs(ip6_h->payload_len), maxsize);
    } 
    
    // Check for UDP in nexthdr
    if ((ip6_h->nexthdr & 0xFF) == 0x11) {
        return parse_udp(pkt, info, maxsize);
    }

    // Unsupported next protocol
    return -1;
}

/**
 *  @brief Obtain the encapsulated protocol from a VLAN tag
 *
 *  @return Protocol number on success, -1 on error
 */
uint16_t vlan_get_encapsulated(void * pkt, parsed_packet * info, size_t maxsize) {
    struct internal_vlan_hdr * vlan_h = NULL;

    // Check size before indexing into vlan header
    if (info->offset + sizeof(struct internal_vlan_hdr) >= maxsize) {
        return -1;
    }

    // Obtain the header and advance the packet offset
    vlan_h = (struct internal_vlan_hdr *)(pkt + info->offset);
    info->offset += sizeof(struct internal_vlan_hdr);

    // Return the encapsulated protocol number
    return htons(vlan_h->h_vlan_encapsulated_proto);
}

/**
 *  @brief Parses the received packet.
 *
 *  Extracts the Source IP and determines the offset of the inner DB packet
 *
 *  @return 0 on success, -1 on error
 */
ssize_t parse_packet(parsed_packet * info, void * pkt, size_t maxsize) {
    uint16_t ethertype = 0;
    struct ethhdr *eth_h = NULL;

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

    // First layer VLAN tag
    if (ethertype == ETH_P_8021Q) {
        ethertype = vlan_get_encapsulated(pkt, info, maxsize);
    }

    // Doubled tagged VLAN
    if (ethertype == ETH_P_8021Q) {
        ethertype = vlan_get_encapsulated(pkt, info, maxsize);
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