use failure::{Error,bail};
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support
use pnet::packet::udp::{MutableUdpPacket};


// Builds an immutable UdpPacket to drop on the wire
pub fn build_udp_packet<'a>(data: &'a [u8], src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16) -> Result<MutableUdpPacket <'a>, Error> 
{ 

    // calculate total length
    let mut length: usize = pnet::packet::ethernet::EthernetPacket::minimum_packet_size();
    length += pnet::packet::udp::MutableUdpPacket::minimum_packet_size();
    length += data.len();

    // the IP layer is variable
    if dst_ip.is_ipv4() && src_ip.is_ipv4() { 
        length+= pnet::packet::ipv4::Ipv4Packet::minimum_packet_size() 
    } 
    else { 
        length += pnet::packet::ipv6::Ipv6Packet::minimum_packet_size();
    }

    // Allocate enough room for the entire packet
    let packet_buffer: Vec<u8> = vec![0;length];

    let mut udp = match MutableUdpPacket::owned(packet_buffer) {
        Some(res) => res,
        None => {
            println!("[!] Could not allocate packet!");
            bail!(-1);
        }
    };

    udp.set_source(rand::random::<u16>());
    udp.set_destination(dst_port);
    udp.set_length(length as u16);
    
    // add the data
    udp.set_payload(data);

    // compute the checksum
    match (src_ip, dst_ip) {
        (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
            let checksum = pnet::packet::udp::ipv4_checksum(&udp.to_immutable(), &src_ip4, &dst_ip4);
            udp.set_checksum(checksum);
        }
        (IpAddr::V6(_src_ip6), IpAddr::V6(_dst_ip6)) => {
            bail!("[-] Ipv6 is unsupported right now")
        }
        _ => {bail!("[-] Unknown IP Address type")}
    }

    return Ok(udp);
}


