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
use server::{exit_with_error2, NetworkSettings};

pub fn get_netmask_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    lazy_static! {
        static ref NETMASK_RE: Regex = Regex::new(r#"(?m)^.*inet (netmask )?(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
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

    None
}

pub fn get_gateway_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    //let command = format!("ip route | grep {} | grep default | grep -o -P  '(?<=via ).*(?= dev)'");
    let output = Command::new("ip")
        .arg("route")
        .arg("show")
        .output()
        .expect("failed to execute `ifconfig`");

    lazy_static! {
        static ref GATEWAY_RE: Regex = Regex::new(r#"(?m).*(via )(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in GATEWAY_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }

    None
}

pub fn get_dns_entries() -> Option<Vec<Ipv4Addr>> {
    let output = Command::new("cat")
        .arg("/etc/resolv.conf")
        .output()
        .expect("failed to execute `ifconfig`");

    lazy_static! {
        static ref GATEWAY_RE: Regex = Regex::new(r#"(?m)(^nameserver)(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }
    let mut dns_entries = Vec::new();

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in GATEWAY_RE.captures_iter(&stdout) {
        println!("Nameservers {:?}", cap);
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            dns_entries.push_back(addr);
            //return Some(addr);
        }
    }

    if dns_entries.length() > 0 {
        Some(dns_entries)
    } else {
        None
    }
}

