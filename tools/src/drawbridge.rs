use failure::{bail, Error};
use libc::timespec;
use std::mem;
use std::path::Path;

use crate::crypto;

// Drawbridge protocol data
#[repr(C, packed)]
pub struct db_data {
    timestamp: timespec,
    port: u16,
}

impl db_data {
    // db_data method to convert to &[u8]
    // which is necessary to use as a packet payload
    pub fn as_bytes(&self) -> &[u8] {
        union Overlay<'a> {
            pkt: &'a db_data,
            bytes: &'a [u8; mem::size_of::<db_data>()],
        }
        unsafe { Overlay { pkt: self }.bytes }
    }
}

/**
 * Convert a u32 to a [u8] in network byte order
 */
fn transform_u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b4, b3, b2, b1];
}

/**
 * Drawbridge protocol payload will result in the following structure:
 *
 * data: db_data
 * sig_size: u32     (must be network byte order)
 * signature: [u8]
 * digest_size: u32  (must be network byte order)
 * digest: [u8]
 *
 */
pub fn build_packet<'a>(unlock_port: u16, private_key_path: String) -> Result<Vec<u8>, Error> {
    let path = Path::new(&private_key_path);
    if !path.exists() {
        bail!("[-] {} does not exist.", path.display())
    }

    // initialize the Drawbridge protocol data
    let mut data = db_data {
        port: unlock_port,
        timestamp: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };

    // get current timestamp
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut data.timestamp);
    }

    // sign the data
    let signature = match crypto::sign_rsa(data.as_bytes(), path) {
        Ok(s) => s,
        Err(e) => {
            bail!("{:?}", e)
        }
    };

    // hash the data
    let digest = crypto::sha256_digest(data.as_bytes()).unwrap();

    // build the final payload
    let mut result = data.as_bytes().to_vec();
    result.extend(&transform_u32_to_array_of_u8(signature.len() as u32));
    result.extend(signature.iter().cloned());
    result.extend(&transform_u32_to_array_of_u8(digest.len() as u32));
    result.extend(digest.iter().cloned());

    return Ok(result);
}
