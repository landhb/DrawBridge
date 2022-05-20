use core::fmt;
use libc::{
    size_t,
    ssize_t,
    c_void
};

pub const SIG_SIZE: usize = 512;
pub const DIGEST_SIZE: usize = 32;

#[repr(C)]
pub struct dbpacket {
    pub timestamp: i64,
    pub port: u16,
}

#[repr(C)]
pub union IpAddress {
    pub addr_6: libc::in6_addr,
    pub addr_4: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct pkey_signature {
    pub s: [u8; SIG_SIZE],
    pub s_size: u32,
    pub digest: [u8; DIGEST_SIZE],
    pub digest_size: u32,
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
    pub sig: pkey_signature,
    pub metadata: dbpacket,
}

extern "C" {

    /**
     * Primary Parsing Interface that must be fuzzed
     */
    pub fn parse_packet(info: *mut packet_info, pkt: *const c_void, maxsize: size_t) -> ssize_t;

    /**
     * Parse signature data from a packet, allocates
     */
    pub fn parse_signature(info: *mut packet_info, pkt: *const c_void, offset: size_t) -> ssize_t;

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
            sig: pkey_signature {
                s: [0u8; SIG_SIZE],
                s_size: 0,
                digest: [0u8; DIGEST_SIZE],
                digest_size: 0,
            },
            metadata: dbpacket {
                timestamp: 0,
                port: 0,
            },
        }
    }
}