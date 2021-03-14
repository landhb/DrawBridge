use failure::{bail, Error};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;

/*
* Grab an interface's src IP
*/
pub fn get_interface_ip(iface: &String) -> Result<IpAddr, Error> {
    let interfaces = pnet::datalink::interfaces();

    for i in interfaces {
        if i.name == *iface {
            return Ok(i.ips[0].ip());
        }
    }
    bail!("[-] Could not find interface IP address")
}

/*
* Get a Linux host's default gateway
*/
pub fn get_default_iface() -> Result<String, Error> {
    let mut file = File::open("/proc/net/route")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut iter = contents.lines();
    let mut res = String::new();
    while let Some(line) = iter.next() {
        let v: Vec<&str> = line.split("\t").collect();
        if v.len() < 3 {
            continue;
        }
        let dst = match u64::from_str_radix(v[1], 16) {
            Ok(a) => a,
            Err(_e) => {
                continue;
            }
        };
        let gateway = match u64::from_str_radix(v[2], 16) {
            Ok(a) => a,
            Err(_e) => {
                continue;
            }
        };
        if dst == 0 && gateway != 0 {
            res = v[0].to_string();
            break;
        }
    }
    Ok(res)
}
