use core::fmt;
use libc::{
    size_t,
    ssize_t,
    c_void
};

#[repr(C)]
pub union IpAddress {
    pub addr_6: libc::in6_addr, // struct in6_addr addr_6;
    pub addr_4: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct pkey_signature {
    pub s: *const u8,    /* Signature */
    pub s_size: u32,     /* Number of bytes in signature */
    pub digest: *const u8,
    pub digest_size: u32, /* Number of bytes in digest */
} 

/**
 * Information parsed from untrusted packets
 */
#[repr(C)]
pub struct packet_info {
    pub version: u8,
    pub port: u16,
    pub offset: usize,
    pub ipstr: [u8;33],
    pub ip: IpAddress,
    pub sig: *const pkey_signature,
}

extern "C" {

    /**
     * Primary Parsing Interface that must be fuzzed
     */
    pub fn parse_packet(pkt: *const c_void, info: *mut packet_info, maxsize: size_t) -> ssize_t;

    /**
     * Parse signature data from a packet, allocates
     */
    pub fn parse_signature(pkt: *const c_void, offset: u32) -> *const pkey_signature;

    /**
     * Cleanup the parsed signature
     */
    pub fn free_signature(sig: *const pkey_signature);
}

impl fmt::Debug for packet_info {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, 
            "version: {}\nport: {}\noffset: {}\n
            ipstr: {:?}\n, sig: {:?}",
            self.version, self.port, self.offset,
            self.ipstr, self.sig
        )
    }
}

impl packet_info {
    pub fn new() -> Self {
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