use failure::{Error,bail};
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support
use pnet::packet::tcp::{MutableTcpPacket,TcpFlags,TcpOption};


use crate::protocol::db_packet;


// Builds an immutable TcpPacket to drop on the wire
pub fn build_tcp_packet<'a>(data: db_packet, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, packet_buffer: &'a mut Vec<u8>) -> Result<(), Error> { //Result<MutableTcpPacket, Error>{

    let mut tcp = match MutableTcpPacket::new(packet_buffer) {
        Some(res) => res,
        None => {
            println!("[!] Could not allocate packet!");
            bail!(-1);
        }
    };

    tcp.set_source(rand::random::<u16>());
    tcp.set_destination(dst_port);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240);
    tcp.set_data_offset(8);
    tcp.set_urgent_ptr(0);
    tcp.set_sequence(rand::random::<u32>());
    tcp.set_options(&[TcpOption::mss(1460), TcpOption::sack_perm(), TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(7)]);
    
    // add the data
    tcp.set_payload(&data.as_bytes());

    // compute the checksum
    match (src_ip, dst_ip) {
    	(IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
    		let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip4, &dst_ip4);
    		tcp.set_checksum(checksum);
    	}
    	(IpAddr::V6(_src_ip6), IpAddr::V6(_dst_ip6)) => {
    		bail!("[-] Ipv6 is unsupported right now")
    	}
    	_ => {bail!("[-] Unknown IP Address type")}
    }

    return Ok(());
}


