use crate::errors::DrawBridgeError::*;
use clap::Parser;
use std::error::Error;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

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
use protocols::{PktWrapper, TcpBuilder, UdpBuilder};
use route::Interface;

/// Arbitrary maximum for the auth packet
const MAX_PACKET_SIZE: usize = 2048;

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
        bits: u32,

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

        /// Auth packet Layer 4 protocol
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
    let key = shellexpand::full(&key).or(Err(InvalidPath))?.to_string();

    // Check if a valid IpAddr was provided
    let target = server.parse::<IpAddr>().or(Err(InvalidIP))?;

    // Determine which interface to use
    let iface = interface.map_or_else(Interface::try_default, |n| Interface::from_name(&n))?;

    // Determine the source IP of the interface
    let src_ip = iface.get_ip().or(Err(InvalidInterface))?;
    println!(
        "[+] Selected Interface {:?}, with address {}",
        iface, src_ip
    );

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
    let data = drawbridge::build_packet(uport, &key).or(Err(NetworkingError))?;

    // Create the packet
    let pkt: PktWrapper = match proto {
        Protocol::Tcp => TcpBuilder::new(src_ip, target, dport, &data)?.build()?,
        Protocol::Udp => UdpBuilder::new(src_ip, target, dport, &data)?.build()?,
    };

    println!(
        "[+] Sending {:?} packet to {}:{} to unlock port {}",
        proto, target, dport, uport
    );

    // Send it
    let n = tx.send_to(pkt, target).or(Err(NetworkingError))?;
    println!("[+] Sent {} bytes", n);
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
fn keygen(alg: Algorithm, bits: u32, out: String) -> Result<(), Box<dyn Error>> {
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
        Algorithm::Rsa => crypto::gen_rsa(bits, priv_path, pub_path)?,
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
