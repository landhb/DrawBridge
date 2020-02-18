#![feature(impl_trait_in_bindings)]

extern crate rand;
extern crate pnet;
extern crate failure; 

// Supported layer 3 protocols
use std::net::{IpAddr}; // TODO: Add Ipv6Addr support

// Supported layer 4 protocols
mod route;
mod protocol;
mod drawbridge;

// channel
use pnet::transport::transport_channel;


use clap::{Arg,App};

use failure::{Error,bail};
use drawbridge::DrawBridgePacket;

// to get around strict send_to types



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

fn main() -> Result<(), Error> {

    // Grab CLI arguments
    let (proto,target,dport,unlock_port,iface) = match parse_args() {
        Ok((proto,target,port,unlock_port,iface)) => (proto,target,port,unlock_port,iface),
        Err(e) => {bail!("{}", e)},
    };

    //Build db_packet for sending
    let db_packet: DrawBridgePacket = match DrawBridgePacket::new(&proto, target, dport, unlock_port, iface) {
        Ok(db_packet) => db_packet,
        _ => {bail!("Error creating db_packet");},
    };


    // Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, db_packet.config) {
        Ok((tx, rx)) => (tx,rx),
        Err(e) => bail!("An error occurred when creating the transport channel: {}", e)
    };


    println!("[+] Sending {} packet to {}:{} to unlock port {}", proto,target,dport,unlock_port);

    //send it
    match tx.send_to(*db_packet.as_packet(), target) {
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
