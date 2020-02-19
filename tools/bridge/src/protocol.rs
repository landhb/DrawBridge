
use crate::drawbridge::DrawBridgePacket;
use std::net::{IpAddr};
use pnet::packet::tcp::{MutableTcpPacket,TcpFlags,TcpOption};
use pnet::packet::udp::{MutableUdpPacket};

use failure::{Error,bail};


pub enum Pkt<'a> {
    TCP(MutableTcpPacket<'a>),
    UDP(MutableUdpPacket<'a>),
}

impl pnet::packet::Packet for Pkt<'_> {
    fn packet(&self) -> &[u8] {
        match self {
            Pkt::TCP(pkt) => pkt.packet(),
            Pkt::UDP(pkt) => pkt.packet(),
        }
    }
    fn payload(&self) -> &[u8] {
        match self {
            Pkt::TCP(pkt) => pkt.payload(),
            Pkt::UDP(pkt) => pkt.payload(),
        }
    }
}


fn build_tcp_packet<'a>(db_packet: &'a mut DrawBridgePacket) -> Option<MutableTcpPacket<'a>> {

    let mut tcp = match MutableTcpPacket::new(db_packet.packet_buffer.as_mut_slice()) {
        Some(res) => res,
        None => {
            println!("[!] Could not allocate packet!");
            return None;        
        }
    };

    tcp.set_source(rand::random::<u16>());
    tcp.set_destination(db_packet.dport);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240);
    tcp.set_data_offset(8);
    tcp.set_urgent_ptr(0);
    tcp.set_sequence(rand::random::<u32>());
    tcp.set_options(&[TcpOption::mss(1460), TcpOption::sack_perm(), TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(7)]);
    
    // add the data
    tcp.set_payload(&db_packet.db_packet_data.as_bytes());

    // compute the checksum
    match (db_packet.src_ip, db_packet.target) {
        (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
            let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip4, &dst_ip4);
            tcp.set_checksum(checksum);
        }
        (IpAddr::V6(_src_ip6), IpAddr::V6(_dst_ip6)) => {
            println!("[-] Ipv6 is unsupported right now");
        }
        _ => { 
            println!("[-] Unknown IP Address type");
            return None;
        },
    }

    return Some(tcp);
}


fn build_udp_packet<'a>(db_packet: &'a mut DrawBridgePacket) -> Option<MutableUdpPacket<'a>>
{ 

    let mut udp = match MutableUdpPacket::new(db_packet.packet_buffer.as_mut_slice()) {
        Some(res) => res,
        None => {
            println!("[!] Could not allocate packet!");
            return None;
        }
    };

    udp.set_source(rand::random::<u16>());
    udp.set_destination(db_packet.dport);
    udp.set_length(8u16 + db_packet.db_packet_data.as_bytes().len() as u16);
    
    // add the data
    udp.set_payload(&db_packet.db_packet_data.as_bytes());

    // compute the checksum
    match (db_packet.src_ip, db_packet.target) {
        (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
            let checksum = pnet::packet::udp::ipv4_checksum(&udp.to_immutable(), &src_ip4, &dst_ip4);
            udp.set_checksum(checksum);
        }
        (IpAddr::V6(_src_ip6), IpAddr::V6(_dst_ip6)) => {
            println!("[-] Ipv6 is unsupported right now");
        }
        _ => { 
            println!("[-] Unknown IP Address type");
            return None;
        }
    }

    return Some(udp);
}

pub fn build_packet<'a>(db_packet: &'a mut DrawBridgePacket) -> Result<Pkt<'a>, Error> {

    match db_packet.proto.as_str() {
        "tcp" => Ok(Pkt::TCP(build_tcp_packet(db_packet).unwrap())),
        "udp" => Ok(Pkt::UDP(build_udp_packet(db_packet).unwrap())),
        _ => bail!("Could not build packet!")
    }
}



