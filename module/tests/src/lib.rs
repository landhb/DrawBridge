#[cfg(test)]
use parser::{packet_info, parse_packet};

#[cfg(test)]
mod ipv4;

#[test]
fn unsupported_protocol() {
    #[rustfmt::skip]
    let junk_packet: &[u8] = &[
        0x08, 0x08, 0x47, 0xF8, 0x08, 0x2B,     // Source Mac
        0x08, 0x00, 0x01, 0xF8, 0x08, 0x2B,     // Destination Mac 
        0x0F, 0x00,                             // Unknown protocol
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
            &mut info as *mut _,
            junk_packet.as_ptr() as _,
            junk_packet.len(),
        )
    };
    println!("{:?}", info);
    assert_eq!(info.version, 0);
    assert_eq!(res, -1);
}
