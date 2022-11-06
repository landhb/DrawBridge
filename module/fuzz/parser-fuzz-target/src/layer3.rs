use etherparse::{InternetSlice, Ipv4HeaderSlice, Ipv6HeaderSlice, SlicedPacket};
use std::error::Error;

/// Abstraction around the Drawbridge layer 3 validation
pub struct Layer3Parser {
    header_len: usize,
    payload_len: usize,
}

impl Layer3Parser {
    /// Determines
    pub fn from_packet(pkt: &SlicedPacket) -> Result<Self, Box<dyn Error>> {
        let iphdr = pkt.ip.as_ref().ok_or("No IP header")?;
        match iphdr {
            InternetSlice::Ipv4(hdr, _) => Self::from_ipv4(hdr),
            InternetSlice::Ipv6(hdr, _) => Self::from_ipv6(hdr),
        }
    }

    /// Offset of the payload after the Layer 3 headers
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Length of the layer 3 payload
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Supported inner protocols
    fn is_supported(num: u8) -> bool {
        match num {
            x if x == etherparse::IpNumber::Tcp as u8 => true,
            x if x == etherparse::IpNumber::Udp as u8 => true,
            _ => false,
        }
    }

    fn from_ipv4(header: &Ipv4HeaderSlice) -> Result<Self, Box<dyn Error>> {
        // Check for valid inner protocol
        if !Self::is_supported(header.protocol()) {
            return Err("Unsupoorted Ipv4 inner protocol".into());
        }

        Ok(Self {
            header_len: ((header.ihl() as usize) * 4),
            payload_len: header.payload_len() as usize,
        })
    }

    fn from_ipv6(header: &Ipv6HeaderSlice) -> Result<Self, Box<dyn Error>> {
        // Check for valid inner protocol
        if !Self::is_supported(header.next_header()) {
            return Err("Unsupoorted Ipv6 inner protocol".into());
        }

        /* Verify
        assert_eq!(info.version, 6);
        unsafe {
            assert_eq!(info.ip.addr_6.s6_addr, hdr.source());
        }*/

        Ok(Self {
            header_len: header.to_header().header_len(),
            payload_len: header.payload_length() as usize,
        })
    }
}
