use crate::errors::DrawBridgeError::*;
use std::error::Error;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
pub fn build_packet<T: AsRef<OsStr>>(
    unlock_port: u16,
    private_key_path: T,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = Path::new(&private_key_path);
    if !path.exists() {
        return Err(DoesNoteExist.into());
    }

    let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // initialize the Drawbridge protocol data
    let mut data = DrawBridgeData {
        port: unlock_port,
        timestamp: secs as i64,
    }
    .to_network_vec();

    // sign the data
    let signature = crypto::sign_rsa(&data, path)?;

    // hash the data
    let digest = crypto::sha256_digest(&data).or(Err(CryptoError))?;

    // build the final payload
    data.extend((signature.len() as u32).to_be_bytes());
    data.extend(signature.iter().cloned());
    data.extend((digest.len() as u32).to_be_bytes());
    data.extend(digest.iter().cloned());

    Ok(data)
}
