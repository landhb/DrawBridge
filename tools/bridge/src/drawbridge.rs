use std::mem;
use libc::timespec;
use failure::{Error,bail};
use std::path::Path;

use crate::crypto;

// Drawbridge protocol data
#[repr(C,packed)]
pub struct db_data {
    timestamp: timespec,
    port: u16,
} 


impl db_data {

    // db_data method to convert to &[u8]
    // which is necessary for most libpnet methods
    pub fn as_bytes(&self) -> &[u8] {

        union Overlay<'a> {
            pkt: &'a db_data,
            bytes: &'a [u8;mem::size_of::<db_data>()],
        }
        unsafe { Overlay { pkt: self }.bytes } 
    }
}

fn transform_u32_to_array_of_u8(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}

fn build_data(unlock_port: u16) -> Result<db_data, Error> {

    // initialize the data
    let mut data =  db_data {
        port: unlock_port,
        timestamp : libc::timespec {
            tv_sec: 0,
            tv_nsec:0,
         },
     };

    // get current timestamp
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME,&mut data.timestamp);
    }

    return Ok(data);
} 


pub fn build_packet<'a>(unlock_port: u16, private_key_path: String) -> Result<Vec<u8>, Error> {

    let path = Path::new(&private_key_path);

    let data: db_data = match build_data(unlock_port) {
        Ok(res) => res,
        Err(e) => {bail!(e)},
    };

    let signature = match crypto::sign_rsa(data.as_bytes(),path) {
        Ok(s) => s,
        Err(e) => {bail!("{:?}",e)},
    };

    let digest = crypto::sha256_digest(data.as_bytes()).unwrap();

    let mut result = data.as_bytes().to_vec();
    result.extend(&transform_u32_to_array_of_u8(signature.len() as u32));
    result.extend(signature.iter().cloned());
    result.extend(&transform_u32_to_array_of_u8(digest.len() as u32));
    result.extend(digest.iter().cloned());

    return Ok(result);
} 
