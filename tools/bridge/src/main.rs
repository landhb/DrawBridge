extern crate rand;
extern crate pnet;
extern crate failure; 

// Supported layer 3 protocols
use std::net::{IpAddr, Ipv4Addr}; // TODO: Add Ipv6Addr support

// Supported layer 4 protocols
mod tcp;
mod route;
mod protocol;

// channel
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4; // base channel type
use pnet::packet::ip::IpNextHeaderProtocols;       // layer 3 
use pnet::transport::TransportProtocol::Ipv4;      // layer 4 

use std::mem;
use failure::{Error,bail};
use protocol::db_packet;

//const ETH_HEADER_SIZE: usize = ;
const MAX_PACKET_SIZE: usize = 2048;


fn main() -> Result<(), Error> {

    let iface = match route::get_default_iface() {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };
    let src_ip = match route::get_interface_ip(&iface) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    println!("[+] Selected Default Interface {}, with address {}", iface, src_ip);


    // TODO, make this dynamically set with client args
    let config: pnet::transport::TransportChannelType = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let target: IpAddr = IpAddr::V4(Ipv4Addr::new(8,8,8,8));

	// Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, config) {
        Ok((tx, rx)) => (tx,rx),
        //Ok(_) => panic!("Unhandled channel type"),
        Err(e) => bail!("An error occurred when creating the transport channel: {}", e)
    };

    let data: db_packet = match protocol::build_data(22) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    // calculate packet size
    let mut buf_size: usize = pnet::packet::ethernet::EthernetPacket::minimum_packet_size();
    buf_size += pnet::packet::ipv4::Ipv4Packet::minimum_packet_size();
    buf_size += pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
    buf_size += mem::size_of::<db_packet>(); 

    // Build the TCP packet
    let mut packet_buffer: Vec<u8> = vec![0;buf_size];

    // fill out the TCP packet
    let pkt: pnet::packet::tcp::MutableTcpPacket = match tcp::build_tcp_packet(data,src_ip, target, 22, &mut packet_buffer){
        Ok(res) => res,
        Err(e) => {bail!(e)}
    };

    // send it
    match tx.send_to(pkt, target) {
        Ok(res) => {
            println!("[+] Sent {} bytes", res);
        }
        Err(e) => {
            println!("[-] Failed to send packet: {}", e);
            bail!(-2);
        }
    }

    return Ok(());
}
