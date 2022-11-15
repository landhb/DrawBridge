use crate::errors::DrawBridgeError::*;
use pnet::datalink::NetworkInterface;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;

/// Route discovered via /proc
struct Route {
    destination: u64,
    gateway: u64,
    iface: String,
}

/// Discovered interface
#[derive(Debug)]
pub struct Interface {
    inner: NetworkInterface,
}

impl Route {
    /// The first few fields of the /proc/net/route table consist of:
    ///
    /// Iface   Destination Gateway
    /// eno1    00000000    0102A8C0
    ///
    /// Which tells us the
    fn from_line(line: &str) -> Result<Self, Box<dyn Error>> {
        let v: Vec<&str> = line.split('\t').collect();
        Ok(Self {
            iface: v.first().ok_or(IndexBounds)?.to_string(),
            destination: u64::from_str_radix(v.get(1).ok_or(IndexBounds)?, 16)?,
            gateway: u64::from_str_radix(v.get(2).ok_or(IndexBounds)?, 16)?,
        })
    }
}

impl Interface {
    pub fn from_name(name: &str) -> Result<Self, Box<dyn Error>> {
        let interfaces = pnet::datalink::interfaces();
        for i in interfaces {
            if i.name == name {
                return Ok(Self { inner: i });
            }
        }
        Err(InvalidInterface.into())
    }

    /// Grab an interface's src IP
    pub fn get_ip(&self) -> Result<IpAddr, Box<dyn Error>> {
        Ok(self.inner.ips.get(0).ok_or(InvalidInterface)?.ip())
    }

    /// Get a Linux host's default gateway
    pub fn try_default() -> Result<Self, Box<dyn Error>> {
        let mut file = File::open("/proc/net/route")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let iter = contents.lines();
        for line in iter {
            let route = match Route::from_line(line) {
                Ok(r) => r,
                _ => continue,
            };

            // A destination address of 0.0.0.0 implies the default
            // gateway
            if route.destination == 0 && route.gateway != 0 {
                return Self::from_name(&route.iface);
            }
        }
        Err(NoDefaultInterface.into())
    }
}
