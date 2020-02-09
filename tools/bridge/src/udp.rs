use failure::{Error,bail};
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support
use pnet::packet::udp::{MutableUdpPacket};


use crate::protocol::db_packet;


// Builds an immutable UdpPacket to drop on the wire
pub fn build_udp_packet<'a>(data: db_packet, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, packet_buffer: &'a mut Vec<u8>) -> Result<(), Error> 
{ 

    let mut udp = match MutableUdpPacket::new(packet_buffer) {
        Some(res) => res,
        None => {
            println!("[!] Could not allocate packet!");
            bail!(-1);
        }
    };

    udp.set_source(rand::random::<u16>());
    udp.set_destination(dst_port);
    udp.set_length(8u16 + data.as_bytes().len() as u16);
    
    // add the data
    udp.set_payload(&data.as_bytes());

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

    return Ok(());
}


