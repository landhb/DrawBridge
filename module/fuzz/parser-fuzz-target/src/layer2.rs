use etherparse::ethernet::{EtherType, Ethernet2Header};
use etherparse::{SlicedPacket, VlanHeader};
use std::error::Error;

/// Abstraction around the Drawbridge layer 2 validation
pub struct Layer2Parser {
    ethhdr: Ethernet2Header,
    vlanhdr: Option<VlanHeader>,
}

impl Layer2Parser {
    // Determines
    pub fn from_packet(pkt: &SlicedPacket) -> Result<Self, Box<dyn Error>> {
        // Mandatory
        let ethhdr = pkt
            .link
            .as_ref()
            .ok_or::<Box<dyn Error>>("No ethernet header".into())?
            .to_header();

        // Optional VLAN tags
        let vlanhdr = pkt.vlan.as_ref().map(|v| v.to_header());

        // If there is a vlan tag ensure the type is supported
        let inner_type = match vlanhdr {
            Some(etherparse::VlanHeader::Single(ref vlanhdr)) => vlanhdr.ether_type,
            Some(etherparse::VlanHeader::Double(ref vlanhdr)) => vlanhdr.outer.ether_type,
            None => ethhdr.ether_type,
        };

        // Verify ether type
        if !Self::is_supported(inner_type) {
            return Err("Ethernet type is not supported".into());
        }
        Ok(Layer2Parser {
            ethhdr: ethhdr.clone(),
            vlanhdr: vlanhdr.clone(),
        })
    }

    // Offset of the payload after the Layer 2 headers
    pub fn get_payload_offset(&self) -> usize {
        let mut offset = self.ethhdr.header_len();
        if let Some(vlan) = &self.vlanhdr {
            offset += vlan.header_len();
        }
        offset
    }

    /// Only these types are supported
    fn is_supported(ether_type: u16) -> bool {
        match EtherType::from_u16(ether_type) {
            Some(EtherType::Ipv4) => true,
            Some(EtherType::Ipv6) => true,
            Some(EtherType::VlanTaggedFrame) => true,
            _ => false,
        }
    }
}
