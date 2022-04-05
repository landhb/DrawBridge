#[macro_use]
extern crate afl;
extern crate libc;

use libc::ssize_t;
use parser::{packet_info, parse_packet, parse_signature};

use etherparse::{ethernet::EtherType, InternetSlice, SlicedPacket};

fn main() {
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::new();
        let res = unsafe { parse_packet(&mut info as *mut _, data.as_ptr() as _, data.len()) };

        // Offset should never exceed received length
        assert!(info.offset < data.len());

        // Double check the parsed protocol information
        compare_results(res, &info, &data);
    });
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::new();
        let mut res = unsafe { parse_packet(&mut info as *mut _, data.as_ptr() as _, data.len()) };

        if res == 0 {
            res = unsafe { parse_signature(&mut info as *mut _, data.as_ptr() as _, data.len()) };
        }

        // Offset should never exceed received length
        assert!(info.offset < data.len());

        // Double check the parsed protocol information
        compare_results(res, &info, &data);
    });
}

fn is_supported(ether_type: u16) -> bool {
    match EtherType::from_u16(ether_type) {
        Some(EtherType::Ipv4) => true,
        Some(EtherType::Ipv6) => true,
        Some(EtherType::VlanTaggedFrame) => true,
        _ => false,
    }
}

fn compare_results(res: ssize_t, info: &packet_info, input: &[u8]) {
    match SlicedPacket::from_ethernet(input) {
        Err(value) => {
            println!("Err {:?}", value);
            assert_eq!(res, -1);
        }
        Ok(value) => {
            println!("link: {:?}", value.link);
            println!("vlan: {:?}", value.vlan);
            println!("ip: {:?}", value.ip);
            println!("transport: {:?}", value.transport);

            /* If not TCP or UDP, then should be error
            if value.transport.is_none() {
                assert_eq!(res, -1);
                return;
            } */

            // Check that there is an ethernet frame
            if value.link.is_none() {
                assert_eq!(res, -1);
                return;
            }

            // Link layer header
            let ethhdr = value.link.as_ref().unwrap().to_header();
            println!("{:#?}", ethhdr);

            // If not a supported type, result should also be < 0
            if !is_supported(ethhdr.ether_type) {
                assert_eq!(res, -1);
                return;
            }

            // Extend the layer 2 header if vlan tagged
            // Assert that non-supported inner vlan protocols are rejected
            let layer2_offset = match value.vlan {
                Some(etherparse::VlanSlice::SingleVlan(data)) => {
                    let vlanhdr = data.to_header();
                    if !is_supported(vlanhdr.ether_type) {
                        assert_eq!(res, -1);
                        return;
                    }
                    ethhdr.header_len() + 4
                }
                Some(etherparse::VlanSlice::DoubleVlan(data)) => {
                    let vlanhdr = data.to_header();
                    if !is_supported(vlanhdr.outer.ether_type) {
                        assert_eq!(res, -1);
                        return;
                    }
                    ethhdr.header_len() + 8
                }
                None => ethhdr.header_len(),
            };

            // Check the IP header parsing is valid
            let ip_payload_offset = match value.ip {
                Some(InternetSlice::Ipv4(hdr, _)) => {
                    println!("{:?}", hdr.to_header());

                    // Invalid packet sizes for data received
                    println!(
                        "Received len {:?}, tot len {:?}",
                        input.len(),
                        hdr.total_len()
                    );
                    if (hdr.total_len() as usize + layer2_offset) > input.len() {
                        assert_eq!(res, -1);
                        return;
                    }

                    // Check for valid inner protocol
                    match hdr.protocol() {
                        x if x == etherparse::IpNumber::Tcp as u8 => {}
                        x if x == etherparse::IpNumber::Udp as u8 => {}
                        _ => {
                            assert_eq!(res, -1);
                            return;
                        }
                    }

                    // Verify
                    assert_eq!(info.version, 4);
                    unsafe {
                        assert_eq!(info.ip.addr_4, u32::from_ne_bytes(hdr.source()));
                    }

                    // IPv4 header length in bytes
                    layer2_offset + ((hdr.ihl() as usize) * 4)
                }
                Some(InternetSlice::Ipv6(hdr, _)) => {
                    // Invalid packet sizes for data received
                    if ((hdr.to_header().header_len() + hdr.payload_length() as usize)
                        + layer2_offset)
                        > input.len()
                    {
                        assert_eq!(res, -1);
                        return;
                    }

                    // Check for valid inner protocol
                    match hdr.next_header() {
                        x if x == etherparse::IpNumber::Tcp as u8 => {}
                        x if x == etherparse::IpNumber::Udp as u8 => {}
                        _ => {
                            assert_eq!(res, -1);
                            return;
                        }
                    }

                    // Verify
                    assert_eq!(info.version, 6);
                    unsafe {
                        assert_eq!(info.ip.addr_6.s6_addr, hdr.source());
                    }

                    // IPv6 header length
                    layer2_offset + hdr.to_header().header_len()
                }
                None => {
                    assert_eq!(res, -1); // non-IP packets shouldn't be valid
                    return;
                }
            };

            //let tcp = etherparse::TcpHeader::from_slice(&input[ip_payload_offset..]).unwrap();
            //println!("{:?}", tcp);

            // Check that the inner transport is valid
            let total_offset = match value.transport {
                Some(etherparse::TransportSlice::Tcp(inner)) => {
                    let header = inner.to_header();
                    println!("{:#?}", header);
                    ip_payload_offset + header.header_len() as usize
                }
                Some(etherparse::TransportSlice::Udp(inner)) => {
                    let header = inner.to_header();
                    println!("{:#?}", header);
                    ip_payload_offset + header.header_len() as usize
                }
                Some(etherparse::TransportSlice::Unknown(inner)) => {
                    println!("Unknown proto {:#?}", inner);
                    assert_eq!(res, -1); // packets shouldn't be valid
                    return;
                }
                None => {
                    assert_eq!(res, -1); // packets shouldn't be valid
                    return;
                }
            };

            // Check offset isn't too large
            println!(
                "
                layer2_offset: {:?}\n
                layer3_offset: {:?}\n
                total_offset {:?}, info->offset {:?}, input lenght: {:?}",
                layer2_offset,
                ip_payload_offset,
                total_offset,
                info.offset,
                input.len()
            );

            // Offset must be less than or equal to input,
            // since there must be data after the input
            if total_offset >= input.len() {
                assert_eq!(res, -1);
                return;
            }

            // Compare correct parsing and offset
            assert_eq!(res, 0);
            assert_eq!(total_offset, info.offset);
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
    let res = unsafe { parse_packet(&mut info as *mut _, data[..rsize].as_ptr() as _, data.len()) };
    println!("{:?}", info);
    compare_results(res, &info, &data[..rsize]);
    assert_eq!(res, -1);
}

#[test]
fn reproduce() {
    use glob::glob_with;
    use glob::MatchOptions;
    use std::fs::File;
    use std::io::Read;

    let mut data = [0u8; 4096];

    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    for entry in glob_with("out/default/crashes/id:00000*", options).unwrap() {
        if let Ok(path) = entry {
            println!("Using crash file: {:?}", path);
            let mut crashfile = File::open(path).unwrap();
            let rsize = crashfile.read(&mut data).unwrap();
            println!("Using packet data {:02X?}", &data[..rsize]);
            println!("Packet length: {:?}", rsize);
            let mut info = packet_info::new();
            let res =
                unsafe { parse_packet(&mut info as *mut _, data[..rsize].as_ptr() as _, rsize) };
            assert!(info.offset < data.len());
            println!("result: {:?} info: {:?}", res, info);
            compare_results(res, &info, &data[..rsize]);
        }
    }
}
