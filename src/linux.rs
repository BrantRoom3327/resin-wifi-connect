use std::error::Error;
use std::process::Command;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use regex::Regex;
use network_manager::{AccessPoint, Connection, ConnectionState, Connectivity, Device, DeviceState,
                      DeviceType, NetworkManager, ServiceState};
use {exit, ExitResult};
use config::Config;
use dnsmasq::start_dnsmasq;
use server::start_server;
use kcf::*;

pub fn get_netmask_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    lazy_static! {
        static ref NETMASK_RE: Regex = Regex::new(
            r#"(?m)^.*inet (netmask )?(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let output = Command::new("ifconfig")
        .arg(adapter)
        .output()
        .expect("failed to execute `ifconfig`");

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in NETMASK_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }

    debug!("returning unspecified for {}", adapter);
    Some(Ipv4Addr::new(0,0,0,0))
}

pub fn get_gateway_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ip")
        .arg("route")
        .arg("show")
        .output()
        .expect("failed to execute `ifconfig`");

    lazy_static! {
        static ref GATEWAY_RE: Regex = Regex::new(
            r#"(?m).*(via )(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in GATEWAY_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }

    debug!("returning unspecified for {}", adapter);
    // incase the adapter isn't up or available, return invalid data but still an ip address.
    Some(Ipv4Addr::new(0,0,0,0))
}

pub fn get_dns_entries() -> Option<Vec<Ipv4Addr>> {
    let output = Command::new("cat")
        .arg("/etc/resolv.conf")
        .output()
        .expect("failed to execute `cat /etc/resolv.conf`");

    lazy_static! {
        static ref GATEWAY_RE: Regex = Regex::new(
            r#"(?m)^nameserver\s*(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }
    let mut dns_entries = Vec::new();

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in GATEWAY_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[1].parse::<Ipv4Addr>() {
            dns_entries.push(addr);
        }
    }

    if dns_entries.len() > 0 {
        return Some(dns_entries);
    }

    debug!("no dns entries found in /etc/resolv.conf");
    None
}
