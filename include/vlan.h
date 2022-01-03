#ifndef VLAN_H
#define VLAN_H 1

#include <stddef.h>
#include <linux/if_ether.h>

/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol (always 0x8100)
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct pvlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
}  __attribute__((packed));

#endif /* VLAN_H */
