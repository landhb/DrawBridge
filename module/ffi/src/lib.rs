use core::fmt;
use std::error::Error;
use libc::{
    size_t,
    ssize_t,
    c_void
};

pub const SIG_SIZE: usize = 512;
pub const DIGEST_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug)]
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

impl Default for pkey_signature {
    fn default() -> Self {
        Self {
            s: [0u8; SIG_SIZE],
            s_size: 0,
            digest: [0u8; DIGEST_SIZE],
            digest_size: 0,
        }
    }
}

impl Default for dbpacket {
    fn default() -> Self {
        Self {
            timestamp: 0,
            port: 0,
        }
    }
}

impl Default for packet_info {
    fn default() -> Self {
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
            sig: pkey_signature::default(),
            metadata: dbpacket::default(),
        }
    }
}

impl dbpacket {
    pub fn from_slice(raw: &[u8]) -> Result<Self, Box<dyn Error>> {
        if raw.len() < std::mem::size_of::<Self>() {
            return Err("Not enough data for payload".into());
        }

        // Attempt to parse the timestamp
        let tsize = std::mem::size_of::<i64>();
        if tsize != SIG_SIZE {
            return Err("Invalid signature lenght".into());
        }

        let timestamp = i64::from_be_bytes(raw[0..tsize].try_into()?);

        // Attempt to parse the unlock port
        let psize = std::mem::size_of::<u16>();
        let port = u16::from_be_bytes(raw[tsize..tsize + psize].try_into()?);

        Ok(Self {
            timestamp,
            port,
        })
    }

    pub fn serialized_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl pkey_signature {
    pub fn from_slice(raw: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut item = pkey_signature::default();
        if raw.len() < std::mem::size_of::<Self>() {
            return Err("Not enough data for signature + digest".into());
        }

        // All sizes are 32bit big endian integers
        let lensize = std::mem::size_of::<u32>();
        let mut offset = 0;

        // Parse and verify the signature length
        item.s_size = u32::from_be_bytes(raw[offset..offset + lensize].try_into()?);
        if item.s_size as usize != SIG_SIZE {
            return Err("Signature length is invalid".into());
        }

        // Copy the signature
        offset = lensize;
        item.s.copy_from_slice(&raw[offset..offset + SIG_SIZE]);

        // Parse and verify the digest length
        offset += SIG_SIZE;
        item.digest_size = u32::from_be_bytes(raw[offset..offset + lensize].try_into()?);
        if item.digest_size as usize != DIGEST_SIZE {
            return Err("Digest length is invalid".into());
        }

        // Copy the digest
        offset += lensize;
        item.digest.copy_from_slice(&raw[offset..offset + DIGEST_SIZE]);
        Ok(item)
    }

    pub fn serialized_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}