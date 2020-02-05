extern crate rand;
extern crate pnet;
extern crate failure; 

// Supported layer 3 protocols
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support

// Supported layer 4 protocols
mod tcp;
mod route;
mod protocol;

// channel
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4; // base channel type
use pnet::packet::ip::IpNextHeaderProtocols;       // layer 3 
use pnet::transport::TransportProtocol::Ipv4;      // layer 4 
use pnet::transport::TransportProtocol::Ipv6; 

use clap::{Arg,App};
use std::mem;
use failure::{Error,bail};
use protocol::db_packet;

//const ETH_HEADER_SIZE: usize = ;
const MAX_PACKET_SIZE: usize = 2048;


fn parse_args() -> Result<(String,IpAddr,u16,u16),Error> {

    let args = App::new("bridge")
        .version("0.1.0")
        .author("landhb <blog.landhb.dev>")
        .about("Drawbridge Client")
        .arg(Arg::with_name("server")
                 .short("s")
                 .long("server")
                 .takes_value(true)
                 .required(true)
                 .help("Address of server running Drawbridge"))
        .arg(Arg::with_name("protocol")
                 .short("p")
                 .long("protocol")
                 .takes_value(true)
                 .required(false)
                 .possible_values(&["tcp", "udp"])
                 .default_value("tcp")
                 .help("Auth packet protocol"))
        .arg(Arg::with_name("dport")
                 .short("d")
                 .long("dport")
                 .takes_value(true)
                 .required(true)
                 .help("Auth packet destination port"))
         .arg(Arg::with_name("uport")
                 .short("u")
                 .long("unlock")
                 .takes_value(true)
                 .required(true)
                 .help("Port to unlock"))
         .arg(Arg::with_name("key")
                 .short("i")
                 .long("key")
                 .takes_value(true)
                 .required(true)
                 .default_value("~/.bridge/db_rsa")
                 .help("Private key for signing"))
        .get_matches();

    // required so safe to unwrap
    let proto = args.value_of("protocol").unwrap().to_string();
    let dtmp = args.value_of("dport").unwrap();
    let utmp = args.value_of("uport").unwrap();

    // check if valid ports were provided
    let (uport,dport) = match (utmp.parse::<u16>(), dtmp.parse::<u16>()) {
        (Ok(uport),Ok(dport)) => (uport,dport),
        _ => {bail!("{}","[-] Ports must be between 1-65535");}
    };

    // check if a valid IpAddr was provided
    let addr = match args.value_of("server").unwrap().parse::<IpAddr>() {
        Ok(e) => e,
        _ => {bail!("{}", "[-] IP address invalid, must be IPv4 or IPv6");},
    };

    return Ok((proto,addr,dport, uport))
}

fn main() -> Result<(), Error> {

    // Grab CLI arguments
    let (proto,target,dport,unlock_port) = match parse_args() {
        Ok((proto,target,port,unlock_port)) => (proto,target,port,unlock_port),
        Err(e) => {bail!("{}", e)},
    };

    let iface = match route::get_default_iface() {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };
    let src_ip = match route::get_interface_ip(&iface) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    println!("[+] Selected Default Interface {}, with address {}", iface, src_ip);

    // Dynamically set the transport protocol
    let config: pnet::transport::TransportChannelType = match (proto.as_str(),target.is_ipv4()) {
        ("tcp",true) => Layer4(Ipv4(IpNextHeaderProtocols::Tcp)),
        ("tcp",false) => Layer4(Ipv6(IpNextHeaderProtocols::Tcp)),
        ("udp",true) => Layer4(Ipv4(IpNextHeaderProtocols::Udp)),
        ("udp",false) => Layer4(Ipv6(IpNextHeaderProtocols::Udp)),
        _ => bail!("[-] Protocol/IpAddr pair not supported!"),
    };

	// Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, config) {
        Ok((tx, rx)) => (tx,rx),
        //Ok(_) => panic!("Unhandled channel type"),
        Err(e) => bail!("An error occurred when creating the transport channel: {}", e)
    };

    let data: db_packet = match protocol::build_data(unlock_port) {
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
    let pkt: pnet::packet::tcp::MutableTcpPacket = match tcp::build_tcp_packet(data,src_ip, target, dport, &mut packet_buffer){
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
