#[macro_use]
extern crate afl;
extern crate libc;

use libc::ssize_t;
use parser::{dbpacket, packet_info, parse_packet, pkey_signature};
use std::error::Error;
use std::mem;

use etherparse::vlan_tagging::VlanSlice;
use etherparse::Ipv4HeaderSlice;
use etherparse::Ipv6HeaderSlice;
use etherparse::LinkSlice;
use etherparse::{ethernet::EtherType, InternetSlice, SlicedPacket};

fn main() {
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::new();
        let res = unsafe { parse_packet(&mut info as *mut _, data.as_ptr() as _, data.len()) };

        // Offset should never exceed received length
        assert!(info.offset <= data.len());

        // Double check the parsed protocol information
        compare_results(res, &info, &data);
    });
}

struct ParserResult {
    res: isize,
    offset: usize,
}

/// Mimics logic in parser_payload()
fn parse_data(mut offset: usize, input: &[u8]) -> (isize, usize) {
    if offset + mem::size_of::<dbpacket>() > input.len() {
        return (-1, offset);
    }

    // Timestamp
    let _timestamp = i64::from_be_bytes(input[offset..offset + 8].try_into().unwrap());
    offset += mem::size_of::<i16>();

    // Port
    let _port = u16::from_be_bytes(input[offset..offset + 2].try_into().unwrap());
    offset += mem::size_of::<u16>();

    if offset + mem::size_of::<pkey_signature>() > input.len() {
        return (-1, offset);
    }

    // Slen
    let slen = u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap());
    offset += mem::size_of::<u32>();

    if slen as usize != parser::SIG_SIZE {
        return (-1, offset);
    }

    // Signature
    offset += parser::SIG_SIZE;

    // Dlen
    let dlen = u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap());
    offset += mem::size_of::<u32>();

    if dlen as usize != parser::DIGEST_SIZE {
        return (-1, offset);
    }

    // Digest
    offset += parser::DIGEST_SIZE;

    (0, offset)
}

fn is_supported(ether_type: u16) -> bool {
    match EtherType::from_u16(ether_type) {
        Some(EtherType::Ipv4) => true,
        Some(EtherType::Ipv6) => true,
        Some(EtherType::VlanTaggedFrame) => true,
        _ => false,
    }
}

/// Ethernet/VLAN Validator
///
/// Returns the offset of the next encpasulated protocol
fn layer_2<'a>(
    res: isize,
    eth: Option<LinkSlice<'a>>,
    vlan: Option<VlanSlice<'a>>,
) -> Result<usize, isize> {
    // Obtain the ethernet header
    let ethhdr = match eth {
        Some(inner) => inner.to_header(),
        None => {
            assert_eq!(res, -1);
            return Err(-1);
        }
    };

    if !is_supported(ethhdr.ether_type) {
        assert_eq!(res, -1);
        return Err(-1);
    }

    // Extend the layer 2 header if vlan tagged
    // Assert that non-supported inner vlan protocols are rejected
    let layer2_offset = match vlan {
        Some(etherparse::VlanSlice::SingleVlan(data)) => {
            let vlanhdr = data.to_header();
            if !is_supported(vlanhdr.ether_type) {
                assert_eq!(res, -1);
                return Err(-1);
            }
            ethhdr.header_len() + 4
        }
        Some(etherparse::VlanSlice::DoubleVlan(data)) => {
            let vlanhdr = data.to_header();
            if !is_supported(vlanhdr.outer.ether_type) {
                assert_eq!(res, -1);
                return Err(-1);
            }
            ethhdr.header_len() + 8
        }
        None => ethhdr.header_len(),
    };

    Ok(layer2_offset)
}

/// IPv4 Validator
///
/// Returns the offset of the next encpasulated protocol
/// and the length of the entire layer 3 payload
fn layer_3_ipv4(
    info: &packet_info,
    hdr: Ipv4HeaderSlice,
    layer2_offset: usize,
    maxsize: usize,
) -> Result<(usize, usize), isize> {
    //println!("{:?}", hdr.to_header());

    // Invalid packet sizes for data received
    if (hdr.total_len() as usize + layer2_offset) > maxsize {
        return Err(-1);
    }

    // Check for valid inner protocol
    match hdr.protocol() {
        x if x == etherparse::IpNumber::Tcp as u8 => {}
        x if x == etherparse::IpNumber::Udp as u8 => {}
        _ => {
            return Err(-1);
        }
    }

    // Verify
    assert_eq!(info.version, 4);
    unsafe {
        assert_eq!(info.ip.addr_4, u32::from_ne_bytes(hdr.source()));
    }

    // IPv4 header length in bytes
    let offset = layer2_offset + ((hdr.ihl() as usize) * 4);
    let len = hdr.payload_len() as usize;
    Ok((offset, len))
}

/// IPv6 Validator
///
/// Returns the offset of the next encpasulated protocol
/// and the length of the entire layer 3 payload
fn layer_3_ipv6(
    info: &packet_info,
    hdr: Ipv6HeaderSlice,
    layer2_offset: usize,
    maxsize: usize,
) -> Result<(usize, usize), isize> {

    // Invalid packet sizes for data received
    if ((hdr.to_header().header_len() + hdr.payload_length() as usize) + layer2_offset) > maxsize {
        return Err(-1);
    }

    // Check for valid inner protocol
    match hdr.next_header() {
        x if x == etherparse::IpNumber::Tcp as u8 => {}
        x if x == etherparse::IpNumber::Udp as u8 => {}
        _ => {
            return Err(-1);
        }
    }

    // Verify
    assert_eq!(info.version, 6);
    unsafe {
        assert_eq!(info.ip.addr_6.s6_addr, hdr.source());
    }

    // IPv6 header length
    let offset = layer2_offset + hdr.to_header().header_len();
    let len = hdr.payload_length() as usize;
    Ok((offset, len))
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


            let layer2_payload_offset = match layer_2(res, value.link, value.vlan) {
                Ok(offset) => offset,
                _ => {
                    assert_eq!(res, -1);
                    return;
                }
            };

            // Check the IP header parsing is valid
            let (layer3_payload_offset, layer3_payload_len) = match value.ip {
                Some(InternetSlice::Ipv4(hdr, _)) => {
                    match layer_3_ipv4(info, hdr, layer2_payload_offset, input.len()) {
                        Ok(offset) => offset,
                        _ => {
                            assert_eq!(res, -1);
                            return;
                        }
                    }
                }
                Some(InternetSlice::Ipv6(hdr, _)) => {
                    match layer_3_ipv6(info, hdr, layer2_payload_offset, input.len()) {
                        Ok(offset) => offset,
                        _ => {
                            assert_eq!(res, -1);
                            return;
                        }
                    }
                }
                None => {
                    assert_eq!(res, -1); // non-IP packets shouldn't be valid
                    return;
                }
            };

            // Check that the inner transport is valid
            let (layer4_payload_offset, layer4_payload_len) = match value.transport {
                Some(etherparse::TransportSlice::Tcp(inner)) => {
                    let header = inner.to_header();
                    println!("{:#?}", header);
                    (
                        layer3_payload_offset + header.header_len() as usize,
                        layer3_payload_len.checked_sub(header.header_len() as usize),
                    )
                }
                Some(etherparse::TransportSlice::Udp(inner)) => {
                    let header = inner.to_header();
                    println!("{:#?}", header);
                    (
                        layer3_payload_offset + header.header_len() as usize,
                        (header.length as usize).checked_sub(header.header_len()),
                    )
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
                layer2_payload_offset,
                layer3_payload_offset,
                layer4_payload_offset,
                info.offset,
                input.len()
            );

            // Is there a payload at all?
            let layer4_payload_len = match layer4_payload_len {
                Some(value) => value,
                None => {
                    assert_eq!(res, -1);
                    return;
                }
            };

            // Offset must be less than or equal to input,
            // since there must be data after the input
            if layer4_payload_offset + layer4_payload_len >= input.len() {
                assert_eq!(res, -1);
                return;
            }

            // Check that there is enough layer4 payload for all our drawbridge needs
            if mem::size_of::<dbpacket>() + mem::size_of::<pkey_signature>() > layer4_payload_len {
                assert_eq!(res, -1);
                return;
            }

            // TODO: Compare Drawbridge data here
            let (payload_res, total_offset) = parse_data(layer4_payload_offset, input);

            // Compare correct parsing and offset
            assert_eq!(res, payload_res);

            // We only care about the offset when the packet is accepted
            if res == 0 {
                assert_eq!(total_offset, info.offset);
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

    for entry in glob_with("out/default/crashes/id:*", options).unwrap() {
        if let Ok(path) = entry {
            println!("Using crash file: {:?}", path);
            let mut crashfile = File::open(path).unwrap();
            let rsize = crashfile.read(&mut data).unwrap();
            println!("Using packet data {:02X?}", &data[..rsize]);
            println!("Packet length: {:?}", rsize);
            let mut info = packet_info::new();
            let res =
                unsafe { parse_packet(&mut info as *mut _, data[..rsize].as_ptr() as _, rsize) };
            assert!(info.offset <= rsize);
            println!("result: {:?} info: {:?}", res, info);
            compare_results(res, &info, &data[..rsize]);
        }
    }
}
