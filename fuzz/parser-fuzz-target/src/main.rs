#[macro_use]
extern crate afl;
extern crate libc;

use libc::ssize_t;
use parser::{parse_packet, packet_info};

fn main() {
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::new();
        let res = unsafe {
            parse_packet(data.as_ptr() as _, &mut info as *mut _, data.len())
        };
        compare_results(res, &info, &data);
    });
}

fn compare_results(res: ssize_t, info: &packet_info, input: &[u8]) {
    use etherparse::{InternetSlice, SlicedPacket};
    match SlicedPacket::from_ethernet(input) {
        Err(value) => {
            println!("Err {:?}", value);
            assert_eq!(res, -1);
        },
        Ok(value) => {
            println!("link: {:?}", value.link);
            println!("vlan: {:?}", value.vlan);
            println!("ip: {:?}", value.ip);
            println!("transport: {:?}", value.transport);
            
            match value.ip {
                Some(InternetSlice::Ipv4(hdr, _)) => {
                    
                    if hdr.total_len() as usize > input.len() {
                        assert_eq!(res, -1);
                        return;
                    }
                    assert_eq!(info.version, 4);
                    unsafe {assert_eq!(info.ip.addr_4, u32::from_ne_bytes(hdr.source()));}
                    match hdr.protocol() {
                        x if x == etherparse::IpNumber::Tcp as u8 => assert_eq!(res, 0),
                        x if x == etherparse::IpNumber::Udp as u8 => assert_eq!(res, 0),
                        _ => assert_eq!(res, -1),
                    }
                },
                Some(InternetSlice::Ipv6(hdr, _)) => {
                    
                    if (hdr.to_header().header_len() + hdr.payload_length() as usize) > input.len() {
                        assert_eq!(res, -1);
                        return;
                    }
                    assert_eq!(info.version, 6);
                    unsafe {assert_eq!(info.ip.addr_6.s6_addr, hdr.source());}
                    match hdr.next_header() {
                        x if x == etherparse::IpNumber::Tcp as u8 => assert_eq!(res, 0),
                        x if x == etherparse::IpNumber::Udp as u8 => assert_eq!(res, 0),
                        _ => assert_eq!(res, -1),
                    }
                },
                None => assert_eq!(res, -1), // non-IP packets shouldn't be valid
            }
        }
    }
}

#[test]
fn start() {
    use std::fs::File;
    use std::io::Read;
    let mut data = [0u8; 4096];
    let mut crashfile = File::open("in/dns_queries.raw").unwrap();
    let rsize = crashfile.read(&mut data).unwrap();
    println!("Using packet data {:02X?}", &data[..rsize]);
    println!("Packet length: {:?}", rsize);
    let mut info = packet_info::new();
    let res = unsafe {
        parse_packet(data[..rsize].as_ptr() as _, &mut info as *mut _, data.len())
    };
    println!("{:?}", info);
    compare_results(res, &info, &data[..rsize]);
    assert_eq!(res, -1);
}

#[test]
fn reproduce() {
    use std::fs::File;
    use std::io::Read;
    use glob::glob_with;
    use glob::MatchOptions;

    let mut data = [0u8; 4096];

    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    for entry in glob_with("out/default/crashes/id*", options).unwrap() {
        if let Ok(path) = entry {
            println!("Using crash file: {:?}", path);
            let mut crashfile = File::open(path).unwrap();
            let rsize = crashfile.read(&mut data).unwrap();
            println!("Using packet data {:02X?}", &data[..rsize]);
            println!("Packet length: {:?}", rsize);
            let mut info = packet_info::new();
            let res = unsafe {
                parse_packet(data[..rsize].as_ptr() as _, &mut info as *mut _, data.len())
            };
            println!("{:?}", info);
            compare_results(res, &info, &data[..rsize]);
        }
    }    
}
