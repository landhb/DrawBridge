#![no_std]
#![feature(lang_items, start, libc)]

extern crate core;
extern crate byteorder;

//use core::prelude::*;
use core::slice;
use self::byteorder::{ByteOrder, BigEndian};

// Defines various language items that need to be around
mod lang;

pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
    Arp = 0x0806,
    WakeOnLan = 0x0842,
    VlanTaggedFrame = 0x8100,
    ProviderBridging = 0x88A8,
    VlanDoubleTaggedFrame = 0x9100
}

impl EtherType {
    ///Tries to convert a raw ether type value to the enum. Returns None if the value does not exist in the enum.
    #[no_mangle]
    pub fn from_u16(value: u16) -> Option<EtherType> {
        use self::EtherType::*;
        match value {
            0x0800 => Some(Ipv4),
            0x86dd => Some(Ipv6),
            0x0806 => Some(Arp),
            0x0842 => Some(WakeOnLan),
            0x88A8 => Some(ProviderBridging),
            0x8100 => Some(VlanTaggedFrame),
            0x9100 => Some(VlanDoubleTaggedFrame),
            _ => None
        }
    }
}

pub struct Ethernet2Header {
    pub source: [u8;6],
    pub destination: [u8;6],
    pub ether_type: u16
}

#[no_mangle]
pub extern "C" fn validate_packet(c_array: *mut u8, length: usize) -> i32 {

    // we know the memory is pre-allocated in xt_listen
    // so we can do this without a problem
    let packet = unsafe { slice::from_raw_parts_mut(c_array, length) };

    // validate that this is an IPv4 or IPv6 packet
    match EtherType::from_u16(BigEndian::read_u16(&packet[12..14])) {
        Some(EtherType::Ipv4) => EtherType::Ipv4,
        Some(EtherType::Ipv6) => EtherType::Ipv6,
        _ => {return -1;}
    }; 


    let _eth = Ethernet2Header {
        source: {
            let mut result: [u8;6] = [0;6];
            result.copy_from_slice(&packet[6..12]);
            result
        },
        destination: {
            let mut result: [u8;6] = [0;6];
            result.copy_from_slice(&packet[..6]);
            result
        },
        ether_type: BigEndian::read_u16(&packet[12..14])
    }; 

    return 1;
}

