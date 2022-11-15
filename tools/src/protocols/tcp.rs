use super::PktWrapper;
use crate::errors::DrawBridgeError::{InvalidIP, OutOfMemory};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};
use std::error::Error;
use std::net::IpAddr;

/// Builder abstraction to build a raw TCP packet
pub struct TcpBuilder<'a> {
    /// The packet being constructed
    pkt: MutableTcpPacket<'a>,

    /// Source IP address
    src: IpAddr,

    /// Destination IP address
    dst: IpAddr,

    /// Destination port
    dport: u16,

    /// Pre-computed payload
    payload: &'a [u8],
}

impl<'a> TcpBuilder<'a> {
    /// Begin building a new TCP packet by providing the source and
    /// destination IP addresses, the destination port, and the
    /// appropriate payload.
    pub fn new(
        src: IpAddr,
        dst: IpAddr,
        dport: u16,
        payload: &'a [u8],
    ) -> Result<Self, Box<dyn Error>> {
        let length = Self::packet_size(payload.len(), dst.is_ipv4());
        Ok(Self {
            pkt: MutableTcpPacket::owned(vec![0; length]).ok_or(OutOfMemory)?,
            src,
            dst,
            dport,
            payload,
        })
    }

    /// Determine minimum packet size to allocate an appropriate backing
    /// store to construct the MutableTcpPacket.
    ///
    /// Adds the Ethernet Header + IP Header + TCP Header + Payload to
    /// determine the minimum length.
    fn packet_size(payload_len: usize, ipv4: bool) -> usize {
        // Layer 2 length
        let mut length: usize = EthernetPacket::minimum_packet_size();

        // Layer 3 length
        length += match ipv4 {
            true => Ipv4Packet::minimum_packet_size(),
            false => Ipv6Packet::minimum_packet_size(),
        };

        // Layer 4 length + payload
        length += MutableTcpPacket::minimum_packet_size();
        length += payload_len;
        length
    }

    /// Finalize the packet, providing a PktWrapper which can be sent
    /// out the raw socket opened via the pnet crate.
    ///
    /// Sets appropriate TCP header information, and computes the
    /// appropriate Layer 4 checksum.
    pub fn build(mut self) -> Result<PktWrapper<'a>, Box<dyn Error>> {
        self.pkt.set_source(rand::random::<u16>());
        self.pkt.set_destination(self.dport);
        self.pkt.set_flags(TcpFlags::SYN);
        self.pkt.set_window(64240);
        self.pkt.set_data_offset(8);
        self.pkt.set_urgent_ptr(0);
        self.pkt.set_sequence(rand::random::<u32>());
        self.pkt.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);

        // Add the payload
        self.pkt.set_payload(self.payload);

        // Compute the checksum
        let checksum = match (self.src, self.dst) {
            (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
                tcp::ipv4_checksum(&self.pkt.to_immutable(), &src_ip4, &dst_ip4)
            }
            (IpAddr::V6(src_ip6), IpAddr::V6(dst_ip6)) => {
                tcp::ipv6_checksum(&self.pkt.to_immutable(), &src_ip6, &dst_ip6)
            }
            _ => {
                println!("[-] Unknown IP Address type");
                return Err(InvalidIP.into());
            }
        };
        self.pkt.set_checksum(checksum);

        // Completed packet
        Ok(PktWrapper::Tcp(self.pkt))
    }
}
