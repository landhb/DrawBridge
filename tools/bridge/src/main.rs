extern crate rand;
extern crate pnet;
extern crate failure; 

// Supported layer 3 protocols
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support

// Supported layer 4 protocols
mod tcp;
mod udp;
mod route;
mod protocol;

// channel
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4; 
use pnet::packet::ip::IpNextHeaderProtocols;       
use pnet::transport::TransportProtocol::Ipv4;      
use pnet::transport::TransportProtocol::Ipv6; 

use clap::{Arg,App};
use std::mem;
use failure::{Error,bail};
use protocol::db_packet;

// to get around strict send_to types
use pnet_sys;
use pnet::transport::TransportSender;

//const ETH_HEADER_SIZE: usize = ;
const MAX_PACKET_SIZE: usize = 2048;

// Function pointer to our Layer4 builder
//type PacketBuilder = fn(db_packet, IpAddr, IpAddr, u16, &mut Vec<u8>) -> Result<dyn pnet::packet::Packet+'static, Error>;// where T: impl pnet::packet::Packet;


fn parse_args() -> Result<(String,IpAddr,u16,u16, String),Error> {

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
        .arg(Arg::with_name("interface")
                 .short("e")
                 .long("interface")
                 .takes_value(true)
                 .required(false)
                 .help("Interface to use"))
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

    let iface = match args.value_of("interface") {
        Some(interface) => interface.to_string(),
        None => {
            match route::get_default_iface() {
                Ok(res) => res.to_string(),
                Err(e) => {bail!("{}", e);},            
            }
        },
    };

    // check if a valid IpAddr was provided
    let addr = match args.value_of("server").unwrap().parse::<IpAddr>() {
        Ok(e) => e,
        _ => {bail!("{}", "[-] IP address invalid, must be IPv4 or IPv6");},
    };

    return Ok((proto,addr,dport, uport, iface))
}


/**
 * Stolen from libpnet and modified to directly send the &[u8] data
 * Removing the restriction to implemente the Packet trait
 */
fn send(tx: &mut TransportSender, packet: &[u8], dst: IpAddr) -> std::io::Result<usize> {
        let mut caddr = unsafe { mem::zeroed() };
        let sockaddr = match dst {
            IpAddr::V4(ip_addr) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip_addr, 0)),
            IpAddr::V6(ip_addr) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip_addr, 0, 0, 0)),
        };
        let slen = pnet_sys::addr_to_sockaddr(sockaddr, &mut caddr);
        let caddr_ptr = (&caddr as *const pnet_sys::SockAddrStorage) as *const pnet_sys::SockAddr;

        pnet_sys::send_to(tx.socket.fd, packet, caddr_ptr, slen)
}

fn main() -> Result<(), Error> {

    // All packets will be ethernet packets
    let mut buf_size: usize = pnet::packet::ethernet::EthernetPacket::minimum_packet_size();

    // Grab CLI arguments
    let (proto,target,dport,unlock_port,iface) = match parse_args() {
        Ok((proto,target,port,unlock_port,iface)) => (proto,target,port,unlock_port,iface),
        Err(e) => {bail!("{}", e)},
    };

    let src_ip = match route::get_interface_ip(&iface) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    println!("[+] Selected Default Interface {}, with address {}", iface, src_ip);

    // Dynamically set the transport protocol, and calculate packet size
    // todo, see if the header size can be calculated and returned in tcp.rs & udp.rs
    let config: pnet::transport::TransportChannelType = match (proto.as_str(),target.is_ipv4()) {
        ("tcp",true) => {
            buf_size += pnet::packet::ipv4::Ipv4Packet::minimum_packet_size();
            buf_size += pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
            Layer4(Ipv4(IpNextHeaderProtocols::Tcp))
        },
        ("tcp",false) => {
            buf_size += pnet::packet::ipv6::Ipv6Packet::minimum_packet_size();
            buf_size += pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
            Layer4(Ipv6(IpNextHeaderProtocols::Tcp))
        },
        ("udp",true) => {
            buf_size += pnet::packet::ipv4::Ipv4Packet::minimum_packet_size();
            buf_size += pnet::packet::udp::MutableUdpPacket::minimum_packet_size();
            Layer4(Ipv4(IpNextHeaderProtocols::Udp))
        },
        ("udp",false) => {
            buf_size += pnet::packet::ipv6::Ipv6Packet::minimum_packet_size();
            buf_size += pnet::packet::udp::MutableUdpPacket::minimum_packet_size();
            Layer4(Ipv6(IpNextHeaderProtocols::Udp))
        },
        _ => bail!("[-] Protocol/IpAddr pair not supported!"),
    };

    // Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, config) {
        Ok((tx, rx)) => (tx,rx),
        Err(e) => bail!("An error occurred when creating the transport channel: {}", e)
    };

    let data: db_packet = match protocol::build_data(unlock_port) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    // calculate the size of the payload
    buf_size += mem::size_of::<db_packet>(); 

    // Allocate enough room for the entire packet
    let mut packet_buffer: Vec<u8> = vec![0;buf_size];

    // fill out the buffer with our packet data
    match proto.as_str() {
        "tcp" => { tcp::build_tcp_packet(data,src_ip,target,dport,&mut packet_buffer)? },
        "udp" => { udp::build_udp_packet(data,src_ip,target,dport,&mut packet_buffer)? },
        _ => bail!("[-] not implemented"),
    }; 

    println!("[+] Sending {} packet to {}:{} to unlock port {}", proto,target,dport,unlock_port);

    // send it
    match send(&mut tx,packet_buffer.as_slice(), target) {
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
