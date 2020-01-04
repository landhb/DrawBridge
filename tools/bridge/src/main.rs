//#![allow(unused_imports)]

extern crate rand;
extern crate pnet;
extern crate failure; 

// Supported layer 3 protocols
use std::net::{IpAddr, Ipv4Addr}; // TODO: Add Ipv6Addr support

// Supported layer 4 protocols
use pnet::packet::tcp::{MutableTcpPacket,TcpFlags,TcpOption};

// channel
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4; // base channel type
use pnet::packet::ip::IpNextHeaderProtocols;       // layer 3 
use pnet::transport::TransportProtocol::Ipv4;      // layer 4 


use libc::timespec;
use failure::{Error,bail};


const MAX_PACKET_SIZE: usize = 2048;

// Drawbridge protocol data
#[repr(C)]
struct db_packet {
    timestamp: timespec,
    port: u16,
} 


fn build_data(unlock_port: u16) -> Result<db_packet, Error> {

    // initialize the data
    let mut data =  db_packet {
        port: unlock_port,
        timestamp : libc::timespec {
            tv_sec: 0,
            tv_nsec:0,
         },
     };

    // get current timestamp
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME,&mut data.timestamp);
    }

    return Ok(data);
} 


// Builds an immutable TcpPacket to drop on the wire
fn build_tcp_packet(dst_port: u16, packet_buffer: Vec<u8>) -> Result<MutableTcpPacket<'static>, Error>{

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

    tcp.set_options(&[TcpOption::mss(1460), TcpOption::sack_perm(), TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(7)]);
    /*let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &partial_packet.iface_ip, &partial_packet.destination_ip);
    tcp.set_checksum(checksum);*/
    //println!("{:?}", tcp.get_source());
    return Ok(tcp);
}

fn main() -> Result<(), Error> {

    // TODO, make this dynamically set with client args
    let config: pnet::transport::TransportChannelType = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let target: IpAddr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));

	// Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, config) {
        Ok((tx, rx)) => (tx,rx),
        //Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
    };


    let data: db_packet = match build_data(22) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    // Build the TCP packet
    let packet_buffer: Vec<u8> = vec![0;MAX_PACKET_SIZE];
   

    // fill out the TCP packet
    let pkt: MutableTcpPacket = match build_tcp_packet(22, packet_buffer){
        Ok(res) => res,
        Err(e) => {bail!(e)}
    };


    // add the data
    pkt.set_payload(data);


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
