//extern crate failure;
extern crate pnet;
extern crate rand;

// Supported layer 3 protocols
use std::net::IpAddr;

// Supported layer 4 protocols
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;

// Transport Channel Types
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportProtocol::Ipv6;

// internal modules
mod crypto;
mod drawbridge;
mod errors;
mod protocols;
mod route;

use crate::errors::DrawBridgeError::*;
use clap::Parser;
use std::error::Error;
use std::io::Write;
use std::path::Path;

const MAX_PACKET_SIZE: usize = 2048;

/// Packet wrapper to pass to TransportSender
/// This allows us to return both MutableTcpPacket
/// and MutableUdpPacket from the builders
enum PktWrapper<'a> {
    Tcp(MutableTcpPacket<'a>),
    Udp(MutableUdpPacket<'a>),
}

/// Supported algorithm types for keys/signing
#[derive(clap::ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
enum Algorithm {
    Rsa,
    Ecdsa,
}

/// Supported layer 4 protocols
#[derive(clap::ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(
    author = "landhb <https://blog.landhb.dev>",
    version = env!("CARGO_PKG_VERSION"),
    about = "Drawbridge Client",
    long_about = None
)]
enum Command {
    /// Generate Drawbridge Keys
    #[command(name = "keygen")]
    KeyGen {
        /// Algorithm to use
        #[arg(value_enum, short, long, default_value_t = Algorithm::Rsa)]
        alg: Algorithm,

        /// Key size in bits
        #[arg(short, long, default_value_t = 4096)]
        bits: usize,

        /// Output file path
        #[arg(short, long, default_value = "~/.drawbridge/db_rsa")]
        out: String,
    },

    /// Authenticate with a Drawbridge server
    Auth {
        /// Address of server running Drawbridge
        #[arg(short, long)]
        server: String,

        /// Specify the outgoing interface to use
        #[arg(short = 'e', long)]
        interface: Option<String>,

        /// Auth packet Layer 4 protocol (tcp/udp)
        #[arg(value_enum, short, long)]
        protocol: Protocol,

        /// Auth packet destination port
        #[arg(short, long)]
        dport: u16,

        /// Port to unlock
        #[arg(short, long)]
        unlock: u16,

        /// Private key for signing
        #[arg(short = 'i', long)]
        key: String,
    },
}

/// tx.send_to's first argument must implement
/// the pnet::packet::Packet Trait
impl pnet::packet::Packet for PktWrapper<'_> {
    fn packet(&self) -> &[u8] {
        match self {
            PktWrapper::Tcp(pkt) => pkt.packet(),
            PktWrapper::Udp(pkt) => pkt.packet(),
        }
    }
    fn payload(&self) -> &[u8] {
        match self {
            PktWrapper::Tcp(pkt) => pkt.payload(),
            PktWrapper::Udp(pkt) => pkt.payload(),
        }
    }
}

/// Method for the auth subcommand,
/// authenticates with a remote Drawbridge Server
fn auth(
    server: String,
    interface: Option<String>,
    proto: Protocol,
    dport: u16,
    uport: u16,
    key: String,
) -> Result<(), Box<dyn Error>> {
    // Expand the path
    let key = match shellexpand::full(&key) {
        Ok(res) => res.to_string(),
        Err(_e) => {
            return Err(InvalidPath.into());
        }
    };

    // Check if a valid IpAddr was provided
    let target = match server.parse::<IpAddr>() {
        Ok(e) => e,
        _ => {
            println!("[-] IP address invalid, must be IPv4 or IPv6");
            return Err(InvalidIP.into());
        }
    };

    // Determine which interface to use
    let iface = match interface {
        Some(i) => i,
        None => match route::get_default_iface() {
            Ok(res) => res,
            Err(_e) => {
                println!("[-] Could not determine default interface");
                return Err(InvalidInterface.into());
            }
        },
    };

    // Determine the source IP of the interface
    let src_ip = match route::get_interface_ip(&iface) {
        Ok(res) => res,
        Err(_e) => {
            println!("[-] Could not determine IP for interface {:?}", iface);
            return Err(InvalidInterface.into());
        }
    };

    println!("[+] Selected Interface {}, with address {}", iface, src_ip);

    // Determine the layer 4 protocol
    let layer4 = match proto {
        Protocol::Tcp => IpNextHeaderProtocols::Tcp,
        Protocol::Udp => IpNextHeaderProtocols::Udp,
    };

    // Dynamically set the transport protocol, and calculate packet size
    // todo, see if the header size can be calculated and returned in tcp.rs & udp.rs
    let config: pnet::transport::TransportChannelType = match target.is_ipv4() {
        true => Layer4(Ipv4(layer4)),
        false => Layer4(Ipv6(layer4)),
    };

    // Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = transport_channel(MAX_PACKET_SIZE, config).or(Err(NetworkingError))?;

    // Build the Drawbridge specific protocol data
    let data = match drawbridge::build_packet(uport, key) {
        Ok(res) => res,
        Err(_e) => {
            return Err(NetworkingError.into());
        }
    };

    // Create the packet
    let pkt: PktWrapper = match proto {
        Protocol::Tcp => PktWrapper::Tcp(protocols::build_tcp_packet(
            data.as_slice(),
            src_ip,
            target,
            dport,
        )?),
        Protocol::Udp => PktWrapper::Udp(protocols::build_udp_packet(
            data.as_slice(),
            src_ip,
            target,
            dport,
        )?),
    };

    println!(
        "[+] Sending {:?} packet to {}:{} to unlock port {}",
        proto, target, dport, uport
    );

    // send it
    match tx.send_to(pkt, target) {
        Ok(res) => {
            println!("[+] Sent {} bytes", res);
        }
        Err(e) => {
            println!("[-] Failed to send packet: {}", e);
            return Err(NetworkingError.into());
        }
    }

    Ok(())
}

/// Helper method to create the .drawbridge parent directory to store
/// keys and configuration.
fn create_key_directory(parent: &Path) -> Result<(), Box<dyn Error>> {
    print!(
        "[!] {} doesn't exist yet, would you like to create it [Y/n]: ",
        parent.display()
    );

    // Flush stdout
    std::io::stdout().flush()?;

    // Receive answer
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Parse answer
    match input {
        x if x == "Y\n" || x == "\n" || x == "y\n" => {
            println!("[*] Creating {:?}", parent.display());
            std::fs::create_dir(parent)?;
            Ok(())
        }
        _ => {
            println!("[-] Specify or create a directory for the new keys.");
            Err(InvalidPath.into())
        }
    }
}

/// Method for the keygen subcommand, generate new
/// Drawbridge keys
fn keygen(alg: Algorithm, bits: usize, out: String) -> Result<(), Box<dyn Error>> {
    // expand the path
    let outfile = match shellexpand::full(&out) {
        Ok(res) => res.to_string(),
        Err(_e) => {
            return Err(InvalidPath.into());
        }
    };

    let outfile_pub = outfile.to_owned() + ".pub";
    let priv_path = Path::new(&outfile);
    let pub_path = Path::new(&outfile_pub);
    let parent = priv_path.parent().ok_or(InvalidPath)?;

    // create the output directory if it doesn't exist
    if !parent.exists() {
        create_key_directory(parent)?;
    }

    println!("[*] Generating {:?} keys...", alg);

    match alg {
        Algorithm::Rsa => crypto::gen_rsa(bits as u32, priv_path, pub_path)?,
        Algorithm::Ecdsa => {
            println!("[-] ECDSA is not implemented yet. Stay tuned.");
            return Err(UnsupportedProtocol.into());
        }
    };

    println!("[+] Generated {:?} keys w/{} bits", alg, bits);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Command::parse();

    // Match on each subcommand to handle different functionality
    match args {
        Command::KeyGen { alg, bits, out } => keygen(alg, bits, out)?,
        Command::Auth {
            server,
            interface,
            protocol,
            dport,
            unlock,
            key,
        } => auth(server, interface, protocol, dport, unlock, key)?,
    }

    Ok(())
}
