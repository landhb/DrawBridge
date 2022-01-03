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
                    assert_eq!(info.version, 4);
                    unsafe {assert_eq!(info.ip.addr_4, u32::from_ne_bytes(hdr.source()));}
                },
                Some(InternetSlice::Ipv6(_hdr, _)) => {
                    assert_eq!(info.version, 6);
                    //assert_eq!(info.ip)
                },
                None => assert_eq!(res, -1), // non-IP packets shouldn't be valid
            }
            assert_eq!(res, 0);
        }
    }
}

#[test]
fn reproduce() {
    use std::fs::File;
    use std::io::Read;
    let mut data = [0u8; 4096];
    let mut crashfile = File::open("out/default/crashes/id:000000,sig:06,src:000000,time:553099,op:havoc,rep:32").unwrap();
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
