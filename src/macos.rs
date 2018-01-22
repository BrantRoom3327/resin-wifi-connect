use std::thread;
use std::process;
use std::time::Duration;
use std::sync::mpsc::{Sender, channel};
use std::error::Error;
use std::process::Command;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use regex::Regex;
use network_manager::{NetworkManager, Device, DeviceState, DeviceType, Connection, AccessPoint,
                      ConnectionState, ServiceState, Connectivity};
use {exit, ExitResult};
use config::{Config, load_resolv_conf};
use dnsmasq::start_dnsmasq;
use server::start_server;

pub fn get_netmask_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ifconfig")
        .arg(adapter)
        .output()
        .expect("failed to execute `ifconfig`");

    let stdout = String::from_utf8(output.stdout).unwrap();

    lazy_static! {
        static ref NETMASK_RE: Regex = Regex::new(r#"(?m)^.*netmask 0x([A-Za-z0-9]*).*$"#).unwrap();
    }

    for cap in NETMASK_RE.captures_iter(&stdout) {
        if cap[1].len() != 8 {
            break;
        }

        let netmask = u32::from_str_radix(&cap[1], 16).unwrap();
        let address = Ipv4Addr::from(netmask);
        return Some(address);
    }

    None
}

pub fn get_gateway_for_adapter(_adapter: &str) -> Option<Ipv4Addr> {
    let output = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()
        .expect("failed to execute `route -n get default`");

    lazy_static! {
        static ref GATEWAY_RE: Regex = Regex::new(r#"(?m).*(gateway: )(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in GATEWAY_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }
    None
}

