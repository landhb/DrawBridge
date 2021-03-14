extern crate failure;
extern crate pnet;
extern crate rand;
//#[macro_use] extern crate failure;

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
mod protocols;
mod route;

use clap::{App, AppSettings, Arg, SubCommand};
use failure::{bail, Error};
use std::io::Write;

const MAX_PACKET_SIZE: usize = 2048;

/**
 * Packet wrapper to pass to TransportSender
 * This allows us to return both MutableTcpPacket
 * and MutableUdpPacket from the builders
 */
enum PktWrapper<'a> {
    Tcp(MutableTcpPacket<'a>),
    Udp(MutableUdpPacket<'a>),
}

/**
 * tx.send_to's first argument must implement
 * the pnet::packet::Packet Trait
 */
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

/**
 * Method for the auth subcommand,
 * authenticates with a remote Drawbridge Server
 */
fn auth(args: &clap::ArgMatches) -> Result<(), Error> {
    // required so safe to unwrap
    let proto = args.value_of("protocol").unwrap();
    let dtmp = args.value_of("dport").unwrap();
    let utmp = args.value_of("uport").unwrap();
    let tmpkey = args.value_of("key").unwrap();

    // expand the path
    let key = match shellexpand::full(tmpkey) {
        Ok(res) => res.to_string(),
        Err(e) => {
            bail!(e)
        }
    };

    // check if valid ports were provided
    let (unlock_port, dport) = match (utmp.parse::<u16>(), dtmp.parse::<u16>()) {
        (Ok(uport), Ok(dport)) => (uport, dport),
        _ => {
            bail!("{}", "[-] Ports must be between 1-65535");
        }
    };

    // check if a valid IpAddr was provided
    let target = match args.value_of("server").unwrap().parse::<IpAddr>() {
        Ok(e) => e,
        _ => {
            bail!("{}", "[-] IP address invalid, must be IPv4 or IPv6");
        }
    };

    let iface = match args.value_of("interface") {
        Some(interface) => interface.to_string(),
        None => match route::get_default_iface() {
            Ok(res) => res,
            Err(e) => {
                bail!(e)
            }
        },
    };

    let src_ip = match route::get_interface_ip(&iface) {
        Ok(res) => res,
        Err(e) => {
            bail!(e)
        }
    };

    println!("[+] Selected Interface {}, with address {}", iface, src_ip);

    // Dynamically set the transport protocol, and calculate packet size
    // todo, see if the header size can be calculated and returned in tcp.rs & udp.rs
    let config: pnet::transport::TransportChannelType = match (proto, target.is_ipv4()) {
        ("tcp", true) => Layer4(Ipv4(IpNextHeaderProtocols::Tcp)),
        ("tcp", false) => Layer4(Ipv6(IpNextHeaderProtocols::Tcp)),
        ("udp", true) => Layer4(Ipv4(IpNextHeaderProtocols::Udp)),
        ("udp", false) => Layer4(Ipv6(IpNextHeaderProtocols::Udp)),
        _ => bail!("[-] Protocol/IpAddr pair not supported!"),
    };

    // Create a new channel, dealing with layer 4 packets
    let (mut tx, _rx) = match transport_channel(MAX_PACKET_SIZE, config) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => bail!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    // build the Drawbridge specific protocol data
    let data = match drawbridge::build_packet(unlock_port, key) {
        Ok(res) => res,
        Err(e) => {
            bail!(e)
        }
    };

    // Create the packet
    let pkt: PktWrapper = match proto {
        "tcp" => PktWrapper::Tcp(protocols::build_tcp_packet(
            data.as_slice(),
            src_ip,
            target,
            dport,
        )?),
        "udp" => PktWrapper::Udp(protocols::build_udp_packet(
            data.as_slice(),
            src_ip,
            target,
            dport,
        )?),
        _ => bail!("[-] not implemented"),
    };

    println!(
        "[+] Sending {} packet to {}:{} to unlock port {}",
        proto, target, dport, unlock_port
    );

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

    Ok(())
}

/**
 * Method for the keygen subcommand, generate new
 * Drawbridge keys
 */
fn keygen(args: &clap::ArgMatches) -> Result<(), Error> {
    let alg = args.value_of("algorithm").unwrap();
    let tmpbits = args.value_of("bits").unwrap();
    let tmpfile = args.value_of("outfile").unwrap();

    // expand the path
    let outfile = match shellexpand::full(tmpfile) {
        Ok(res) => res.to_string(),
        Err(e) => {
            bail!(e)
        }
    };

    let outfile_pub = outfile.to_owned() + ".pub";
    let priv_path = std::path::Path::new(&outfile);
    let pub_path = std::path::Path::new(&outfile_pub);
    let parent = priv_path.parent().unwrap();

    // create the output directory if it doesn't exist
    if !parent.exists() {
        print!(
            "[!] {} doesn't exist yet, would you like to create it [Y/n]: ",
            parent.display()
        );
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");
        if input == "Y\n" || input == "\n" || input == "y\n" {
            println!("[*] Creating {:?}", parent.display());
            std::fs::create_dir(parent)?;
        } else {
            bail!("[-] Specify or create a directory for the new keys.")
        }
    }

    let bits = match tmpbits.parse::<u32>() {
        Ok(b) => b,
        Err(e) => {
            bail!(e)
        }
    };

    println!("[*] Generating {} keys...", alg);

    match alg {
        "rsa" => crypto::gen_rsa(bits, priv_path, pub_path)?,
        "ecdsa" => {
            bail!("[-] ECDSA is not implemented yet. Stay tuned.")
        }
        _ => unreachable!(),
    };

    println!("[+] Generated {} keys w/{} bits", alg, bits);
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = App::new("db")
        .version("1.0.0")
        .author("landhb <https://blog.landhb.dev>")
        .about("Drawbridge Client")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generate Drawbridge Keys")
                .arg(
                    Arg::with_name("algorithm")
                        .short("a")
                        .long("alg")
                        .takes_value(true)
                        .required(true)
                        .possible_values(&["rsa", "ecdsa"])
                        .default_value("rsa")
                        .help("Algorithm to use"),
                )
                .arg(
                    Arg::with_name("bits")
                        .short("b")
                        .long("bits")
                        .takes_value(true)
                        .required(true)
                        .default_value("4096")
                        .help("Key size"),
                )
                .arg(
                    Arg::with_name("outfile")
                        .short("o")
                        .long("out")
                        .takes_value(true)
                        .required(true)
                        .default_value("~/.drawbridge/db_rsa")
                        .help("Output file name"),
                ),
        )
        .subcommand(
            SubCommand::with_name("auth")
                .about("Authenticate with a Drawbridge server")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .long("server")
                        .takes_value(true)
                        .required(true)
                        .help("Address of server running Drawbridge"),
                )
                .arg(
                    Arg::with_name("interface")
                        .short("e")
                        .long("interface")
                        .takes_value(true)
                        .help("Specify the outgoing interface to use"),
                )
                .arg(
                    Arg::with_name("protocol")
                        .short("p")
                        .long("protocol")
                        .takes_value(true)
                        .required(false)
                        .possible_values(&["tcp", "udp"])
                        .default_value("tcp")
                        .help("Auth packet protocol"),
                )
                .arg(
                    Arg::with_name("dport")
                        .short("d")
                        .long("dport")
                        .takes_value(true)
                        .required(true)
                        .help("Auth packet destination port"),
                )
                .arg(
                    Arg::with_name("uport")
                        .short("u")
                        .long("unlock")
                        .takes_value(true)
                        .required(true)
                        .help("Port to unlock"),
                )
                .arg(
                    Arg::with_name("key")
                        .short("i")
                        .long("key")
                        .takes_value(true)
                        .required(true)
                        .default_value("~/.drawbridge/db_rsa")
                        .help("Private key for signing"),
                ),
        )
        .get_matches();

    // Match on each subcommand to handle different functionality
    match args.subcommand() {
        ("auth", Some(auth_args)) => auth(auth_args)?,
        ("keygen", Some(keygen_args)) => keygen(keygen_args)?,
        _ => {
            println!("Please provide a valid subcommand. Run db -h for more information.");
        }
    }

    return Ok(());
}
