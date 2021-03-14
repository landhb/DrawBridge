use failure::{bail, Error};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::udp::MutableUdpPacket;
use std::net::IpAddr;

// Builds an immutable UdpPacket to drop on the wire
pub fn build_udp_packet<'a>(
    data: &'a [u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<MutableUdpPacket<'a>, Error> {
    // calculate total length
    let mut length: usize = pnet::packet::ethernet::EthernetPacket::minimum_packet_size();
    length += pnet::packet::udp::MutableUdpPacket::minimum_packet_size();
    length += data.len();

    // the IP layer is variable
    if dst_ip.is_ipv4() && src_ip.is_ipv4() {
        length += pnet::packet::ipv4::Ipv4Packet::minimum_packet_size()
    } else {
        length += pnet::packet::ipv6::Ipv6Packet::minimum_packet_size();
    }

    // Allocate enough room for the entire packet
    let packet_buffer: Vec<u8> = vec![0; length];

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
            let checksum =
                pnet::packet::udp::ipv4_checksum(&udp.to_immutable(), &src_ip4, &dst_ip4);
            udp.set_checksum(checksum);
        }
        (IpAddr::V6(src_ip6), IpAddr::V6(dst_ip6)) => {
            let checksum =
                pnet::packet::udp::ipv6_checksum(&udp.to_immutable(), &src_ip6, &dst_ip6);
            udp.set_checksum(checksum);
        }
        _ => {
            bail!("[-] Unknown IP Address type")
        }
    }

    return Ok(udp);
}

// Builds an immutable TcpPacket to drop on the wire
pub fn build_tcp_packet<'a>(
    data: &'a [u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<MutableTcpPacket<'a>, Error> {
    // calculate total length
    let mut length: usize = pnet::packet::ethernet::EthernetPacket::minimum_packet_size();
    length += pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
    length += data.len();

    // the IP layer is variable
    if dst_ip.is_ipv4() && src_ip.is_ipv4() {
        length += pnet::packet::ipv4::Ipv4Packet::minimum_packet_size()
    } else {
        length += pnet::packet::ipv6::Ipv6Packet::minimum_packet_size();
    }

    // Allocate enough room for the entire packet
    let packet_buffer: Vec<u8> = vec![0; length];

    let mut tcp = match MutableTcpPacket::owned(packet_buffer) {
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
    tcp.set_options(&[
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]);

    // add the data
    tcp.set_payload(data);

    // compute the checksum
    match (src_ip, dst_ip) {
        (IpAddr::V4(src_ip4), IpAddr::V4(dst_ip4)) => {
            let checksum =
                pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip4, &dst_ip4);
            tcp.set_checksum(checksum);
        }
        (IpAddr::V6(src_ip6), IpAddr::V6(dst_ip6)) => {
            let checksum =
                pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip6, &dst_ip6);
            tcp.set_checksum(checksum);
        }
        _ => {
            bail!("[-] Unknown IP Address type")
        }
    }

    return Ok(tcp);
}
