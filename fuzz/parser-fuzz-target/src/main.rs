#[macro_use]
extern crate afl;
extern crate libc;

use libc::{
    size_t,
    ssize_t,
    c_void
};

#[repr(C)]
union IpAddress {
    addr_6: libc::in6_addr, // struct in6_addr addr_6;
    addr_4: u32,
}

#[repr(C)]
struct pkey_signature {
    s: *const u8,    /* Signature */
    s_size: u32,     /* Number of bytes in signature */
    digest: *const u8,
    digest_size: u32, /* Number of bytes in digest */
} 

/**
 * Information parsed from untrusted packets
 */
#[repr(C)]
struct packet_info {
    version: u8,
    port: u16,
    offset: usize,
    ipstr: [u8;33],
    ip: IpAddress,
    sig: *const pkey_signature,
}

extern "C" {
    fn parse_packet(pkt: *const c_void, info: *mut packet_info, maxsize: size_t) -> ssize_t;
}

impl packet_info {
    fn new() -> Self {
        Self {
            version: 0,
            port: 0,
            offset: 0,
            ipstr: [0u8; 33],
            ip: IpAddress {
                addr_6: libc::in6_addr {
                    s6_addr: [0u8; 16],
                }
            },
            sig: core::ptr::null()
        }
    }
}

fn main() {
    fuzz!(|data: &[u8]| {
        let mut info = packet_info::new();
        let res = unsafe {
            parse_packet(data.as_ptr() as _, &mut info as *mut _, data.len())
        };
        assert_eq!(res, -1);
    });
}
