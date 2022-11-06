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

mod layer2;
use layer2::Layer2Parser;

mod layer3;
use layer3::Layer3Parser;

fn main() {
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::default();
        let res = unsafe { parse_packet(&mut info as *mut _, data.as_ptr() as _, data.len()) };

        // Offset should never exceed received length
        assert!(info.offset <= data.len());

        // Double check the parsed protocol information
        compare_results(res, &info, &data);
    });
}

/// Mimics logic in parser_payload()
fn parse_data(mut offset: usize, input: &[u8]) -> Result<(isize, usize), Box<dyn Error>> {
    // Metadata
    let metadata = dbpacket::from_slice(&input[offset..])?;
    offset += metadata.serialized_size();

    // Signature + Digest
    let sig = pkey_signature::from_slice(&input[offset..])?;
    offset += sig.serialized_size();
    Ok((0, offset))
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

fn compare_results(res: ssize_t, info: &packet_info, input: &[u8]) -> Result<(), Box<dyn Error>> {
    let packet = match SlicedPacket::from_ethernet(input) {
        Err(value) => {
            println!("Err {:?}", value);
            assert_eq!(res, -1);
            return Err("Invalid SlicedPacket".into());
        }
        Ok(value) => {
            println!("link: {:?}", value.link);
            println!("vlan: {:?}", value.vlan);
            println!("ip: {:?}", value.ip);
            println!("transport: {:?}", value.transport);
            value
        }
    };

    // Assert that layer 2 is either valid or correctly determined to be
    // invalid by the code being fuzzed
    let layer2 = Layer2Parser::from_packet(&packet)?;
    let layer2_payload_offset = layer2.get_payload_offset();
    /*let layer2_payload_offset = match layer_2(res, packet.link, packet.vlan) {
        Ok(offset) => offset,
        _ => {
            assert_eq!(res, -1);
            return;
        }
    };*/

    // Assert that layer 3 is either valid or correctly determined to be
    // invalid by the code being fuzzed
    let (layer3_payload_offset, layer3_payload_len) = match packet.ip {
        Some(InternetSlice::Ipv4(hdr, _)) => {
            match layer_3_ipv4(info, hdr, layer2_payload_offset, input.len()) {
                Ok(offset) => offset,
                _ => {
                    assert_eq!(res, -1);
                    return Err("Invalid Ipv4".into());
                }
            }
        }
        Some(InternetSlice::Ipv6(hdr, _)) => {
            match layer_3_ipv6(info, hdr, layer2_payload_offset, input.len()) {
                Ok(offset) => offset,
                _ => {
                    assert_eq!(res, -1);
                    return Err("Invalid Ipv6".into());
                }
            }
        }
        None => {
            assert_eq!(res, -1); // non-IP packets shouldn't be valid
            return Err("Invalid layer3 protocol".into());
        }
    };

    // Check that the inner transport is valid
    let (layer4_payload_offset, layer4_payload_len) = match packet.transport {
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
            return Err("Invalid layer4 protocol".into());
        }
        None => {
            assert_eq!(res, -1); // packets shouldn't be valid
            return Err("Invalid layer4 protocol".into());
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
            return Err("No layer4 payload".into());
        }
    };

    // Offset must be less than or equal to input,
    // since there must be data after the input
    if layer4_payload_offset + layer4_payload_len >= input.len() {
        assert_eq!(res, -1);
        return Err("Offsets larger than input data".into());
    }

    // Check that there is enough layer4 payload for all our drawbridge needs
    if mem::size_of::<dbpacket>() + mem::size_of::<pkey_signature>() > layer4_payload_len {
        assert_eq!(res, -1);
        return Err("Not enough data in payload".into());
    }

    // TODO: Compare Drawbridge data here
    let (payload_res, total_offset) =
        parse_data(layer4_payload_offset, input).unwrap_or((-1, layer4_payload_offset));

    // Compare correct parsing and offset
    assert_eq!(res, payload_res);

    // We only care about the offset when the packet is accepted by the C code
    if res == 0 {
        assert_eq!(total_offset, info.offset);
    }

    Ok(())
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
    let mut info = packet_info::default();
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
            let mut info = packet_info::default();
            let res =
                unsafe { parse_packet(&mut info as *mut _, data[..rsize].as_ptr() as _, rsize) };
            assert!(info.offset <= rsize);
            println!("result: {:?} info: {:?}", res, info);
            compare_results(res, &info, &data[..rsize]);
        }
    }
}
