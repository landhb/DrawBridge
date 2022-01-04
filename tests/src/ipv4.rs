//use etherparse::PacketBuilder;
use parser::{packet_info, parse_packet};

fn vlan_tagged_ipv4_proper() {
    #[rustfmt::skip]
    let junk_packet: &[u8] = &[
        0xC4, 0x7F, 0xC4, 0x23, 0x7F, 0x9F, // Source Mac
        0x87, 0xE3, 0x10, 0x25, 0x19, 0x00, // Destination Mac
        0x81, 0x00,                         // 802.1Q VLAN
        0x81, 0x00, 0x08, 0x00,             // VLAN Header, Encapsulated IPv4

        0x45,                               // IPv4, Header Length 20
        0x00,                               // Priority & Type
        0x00, 0x22,                         // Total Length = 34
        0x40, 0xA9, 0x40, 0x00, 0x40,
        0x11, 0xF9, 0xC9, 0x7F, 0x00,
        0x00, 0x01, 0x7F, 0x00, 0x00,
        0x01,

        // UDP Header
        0xB2, 0xE1, // Source Port
        0x00, 0x35, // Destination Port
        0x00, 0x10, // Total Length 8 + payload
        0x66, 0x5F, 

        // Payload
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    let mut info = packet_info::new();
    let res = unsafe {
        parse_packet(
            junk_packet.as_ptr() as _,
            &mut info as *mut _,
            junk_packet.len(),
        )
    };
    println!("{:?}", info);
    assert_eq!(info.version, 4); // Successfully parsed IPv4
    assert_eq!(info.offset, 14 + 4 + 20 + 8); // Ethernet + VLAN + IPv4 + UDP
    assert_eq!(res, 0); // Still negative due to garbage inner protocol
}

#[test]
fn vlan_tagged_ipv4() {
    #[rustfmt::skip]
    let junk_packet: &[u8] = &[       
        0xC4, 0x7F, 0xC4, 0x23, 0x7F, 0x9F,     // Source Mac
        0x87, 0xE3, 0x10, 0x25, 0x19, 0x00,     // Destination Mac
        0x81, 0x00,                             // 802.1Q VLAN
        0x81, 0x00, 0x08, 0x00,                 // VLAN Header, Encapsulated IPv4
        
        0x49,                                   // IPv4, Header Length 36
        0x00,                                   // Priority & Type
        0x00, 0x30,                             // Total Length
        0x14, 0x00, 0x00, 0x81, 0x00, 0x08,
        0x00, 0x83, 0x00, 0x14, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x81, 0x00,
        0x08, 0x00, 0x49, 0x00, 0x83, 0x00,
        0x14, 0x00, 0x00, 0x81, 0x00, 0x08,
        0x00, 0x83, 0x00, 0x14, 0x00, 0x00,
        0xE8, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x81, 0x00,
        0xFF, 0x01, 0x00, 0x00, 0x00, 0x07
    ];

    let mut info = packet_info::new();
    let res = unsafe {
        parse_packet(
            junk_packet.as_ptr() as _,
            &mut info as *mut _,
            junk_packet.len(),
        )
    };
    println!("{:?}", info);
    assert_eq!(info.version, 4); // Successfully parsed IPv4
    assert_eq!(res, -1); // Still negative due to garbage inner protocol
}

#[test]
fn mismatched_ether_ip_versions() {
    #[rustfmt::skip]
    let junk_packet: &[u8] = &[
        0x08, 0x08, 0x47, 0xF8, 0x08, 0x2B,     // Source Mac
        0x08, 0x00, 0x01, 0xF8, 0x08, 0x2B,     // Destination Mac 
        0x08, 0x00,                             // Encapsulated IPv4
        0x01,                                   // IP version 0 ??, Length 4
        0xE0,                                   // IPv4 Priority & Type
        0x08, 0x08,                             // Total Length
        0x08, 0x08, 0x03, 0xE8, 0x08, 0x06, 0x08,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0x81, 0xE0, 0x08, 0x08,
        0x08, 0x08, 0x03, 0xE8, 0x08, 0x06, 0x08, 0x81,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0xE0, 0x08, 0x08
    ];

    let mut info = packet_info::new();
    let res = unsafe {
        parse_packet(
            junk_packet.as_ptr() as _,
            &mut info as *mut _,
            junk_packet.len(),
        )
    };
    println!("{:?}", info);
    assert_eq!(info.version, 0);
    assert_eq!(res, -1);
}

#[test]
fn garbage_ipv4_total_size() {
    #[rustfmt::skip]
    let junk_packet: &[u8] = &[
        0x08, 0x08, 0x47, 0xF8, 0x08, 0x2B,     // Source Mac
        0x08, 0x00, 0x01, 0xF8, 0x08, 0x2B,     // Destination Mac 
        0x08, 0x00,                             // Encapsulated IPv4
        0x4F,                                   // IP version 4, Header Length 60
        0xE0,                                   // IPv4 Priority & Type
        0x08, 0x08,                             // Total Length > Packet Length
        0x08, 0x08, 0x03, 0xE8, 0x08, 0x06, 0x08,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0x81, 0xE0, 0x08, 0x08,
        0x08, 0x08, 0x03, 0xE8, 0x08, 0x06, 0x08, 0x81,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
        0x81, 0x81, 0x81, 0xE0, 0x08, 0x08
    ];

    let mut info = packet_info::new();
    let res = unsafe {
        parse_packet(
            junk_packet.as_ptr() as _,
            &mut info as *mut _,
            junk_packet.len(),
        )
    };
    println!("{:?}", info);
    assert_eq!(info.version, 0);
    assert_eq!(res, -1);
}