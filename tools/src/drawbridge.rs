use crate::errors::DrawBridgeError::*;
use std::error::Error;
use std::path::Path;

use crate::crypto;

/// Drawbridge protocol data
pub struct DrawBridgeData {
    timestamp: i64,
    port: u16,
}

impl DrawBridgeData {
    /// Serialize DrawBridgeData into a packed
    /// format with each field in network endian
    pub fn to_network_vec(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend(self.timestamp.to_be_bytes());
        res.extend(self.port.to_be_bytes());
        res
    }
}

/// Drawbridge protocol payload will result in the following structure:
///
/// data: DrawBridgeData
/// sig_size: u32     (must be network byte order)
/// signature: [u8]
/// digest_size: u32  (must be network byte order)
/// digest: [u8]
pub fn build_packet<'a>(
    unlock_port: u16,
    private_key_path: String,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = Path::new(&private_key_path);
    if !path.exists() {
        return Err(DoesNoteExist.into());
    }

    // Init tempsepc
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // get current timestamp
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut timestamp);
    }

    // initialize the Drawbridge protocol data
    let mut data = DrawBridgeData {
        port: unlock_port,
        timestamp: timestamp.tv_sec,
    }
    .to_network_vec();

    // sign the data
    let signature = match crypto::sign_rsa(&data, path) {
        Ok(s) => s,
        Err(e) => {
            return Err(e);
        }
    };

    // hash the data
    let digest = crypto::sha256_digest(&data).or(Err(CryptoError))?;

    // build the final payload
    data.extend((signature.len() as u32).to_be_bytes());
    data.extend(signature.iter().cloned());
    data.extend((digest.len() as u32).to_be_bytes());
    data.extend(digest.iter().cloned());

    return Ok(data);
}
