use super::PktWrapper;
use crate::errors::DrawBridgeError::{InvalidIP, OutOfMemory};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption};
use std::error::Error;
use std::net::IpAddr;

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
    pub fn new(
        src: IpAddr,
        dst: IpAddr,
        dport: u16,
        payload: &'a [u8],
    ) -> Result<Self, Box<dyn Error>> {
        // Layer 2 length
        let mut length: usize = EthernetPacket::minimum_packet_size();

        // Layer 3 length
        length += match dst.is_ipv4() {
            true => Ipv4Packet::minimum_packet_size(),
            false => Ipv6Packet::minimum_packet_size(),
        };

        // Layer 4 length + payload
        length += MutableTcpPacket::minimum_packet_size();
        length += payload.len();
        Ok(Self {
            pkt: MutableTcpPacket::owned(vec![0; length]).ok_or(OutOfMemory)?,
            src,
            dst,
            dport,
            payload,
        })
    }

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
