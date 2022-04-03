#ifndef VLAN_H
#define VLAN_H 1

#include <stddef.h>
#include <linux/if_ether.h>

/**
 *  vlan_hdr
 *  @h_vlan_TCI: priority and VLAN ID
 *  @h_vlan_encapsulated_proto: packet type ID or len
 */
struct internal_vlan_hdr {
    __be16      h_vlan_TCI;
    __be16      h_vlan_encapsulated_proto;
}  __attribute__((packed));

#endif /* VLAN_H */
