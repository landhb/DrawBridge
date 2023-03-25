use etherparse::{SlicedPacket, TcpHeader, TransportSlice, UdpHeader};
use std::error::Error;

/// Abstraction around the Drawbridge layer 4 validation
#[allow(unused)]
pub struct Layer4Parser {
    header_len: usize,
    payload_len: usize,
}

impl Layer4Parser {
    /// Determines
    pub fn from_packet(pkt: &SlicedPacket) -> Result<Self, Box<dyn Error>> {
        let transport = pkt.transport.as_ref().ok_or("No valid Layer4 header")?;
        match transport {
            TransportSlice::Tcp(hdr) => Self::from_tcp(hdr.to_header()),
            TransportSlice::Udp(hdr) => Self::from_udp(hdr.to_header()),
            _ => Err("Unsupported Layer 4 Protocol".into()),
        }
    }

    /// Offset of the payload after the Layer 3 headers
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Length of the layer 3 payload
    #[allow(unused)]
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// TCP Parser
    fn from_tcp(header: TcpHeader) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            header_len: header.header_len() as usize,
            payload_len: 0,
        })
    }

    /// UDP Parser
    fn from_udp(header: UdpHeader) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            header_len: header.header_len(),
            payload_len: (header.length as usize)
                .checked_sub(header.header_len())
                .ok_or("Invalid UDP length")?,
        })
    }
}
