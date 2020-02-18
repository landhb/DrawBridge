use failure::Error;
use std::mem;
use libc::timespec;

// Drawbridge protocol data
#[repr(C,packed)]
pub struct db_packet {
    timestamp: timespec,
    port: u16,
} 


impl db_packet {

    // db_packet method to convert to &[u8]
    // which is necessary for most libpnet methods
    pub fn as_bytes(&self) -> &[u8] {

        union Overlay<'a> {
            pkt: &'a db_packet,
            bytes: &'a [u8;mem::size_of::<db_packet>()],
        }
        unsafe { Overlay { pkt: self }.bytes } 
    }
}

pub fn build_data(unlock_port: u16) -> Result<db_packet, Error> {

    // initialize the data
    let mut data =  db_packet {
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