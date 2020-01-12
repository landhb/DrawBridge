use failure::{Error,bail};
use pnet::packet::tcp::{MutableTcpPacket,TcpFlags,TcpOption};

// need a psuedohdr to compute the IP checksum, which requires knowledge of some basic
// fields in the IP header
/*
struct psuedohdr  {
    struct in_addr source_address;
    struct in_addr dest_address;
    unsigned char place_holder;
    unsigned char protocol;
    unsigned short length;
}*/



// Builds an immutable TcpPacket to drop on the wire
pub fn build_tcp_packet(dst_port: u16, packet_buffer: &mut Vec<u8>) -> Result<MutableTcpPacket, Error>{

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
    //let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable());//, &partial_packet.iface_ip, &partial_packet.destination_ip);
    //tcp.set_checksum(checksum);
    //println!("{:?}", tcp.get_source());
    return Ok(tcp);
}
