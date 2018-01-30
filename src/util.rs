
pub fn set_ip_and_netmask(ip_address: &str, netmask: &str, interface_name: &str) -> Result<(), String> {

    let ifconfig_str = "ifconfig ".to_string() + interface_name + ip_address + " netmask " + netmask;

    //println!("Do the ifconfig command {}", ifconfig_str);
    let output = Command::new("sh")
        .arg("-c")
        .arg(ifconfig_str)
        .output()
        .expect("failed to execute process");

    let out = output.stdout;
    if out.len() != 0 {
        return Err(String::from_utf8(out).unwrap());
    }
    Ok(())
}

pub fn set_gateway(gateway: &str) -> Result<(), String> {

    // TODO: Make sure the route does not already exist, if so its a noop.

    let output = Command::new("sh")
        .arg("-c")
        .arg("route add default ")
        .arg(gateway)
        .output()
        .expect("failed to execute process");

    let out = output.stdout;
    if out.len() != 0 {
        return Err(String::from_utf8(out).unwrap());
    }
    Ok(())
}

pub fn set_dns(dns_entries: &Vec<Ipv4Addr>) -> Result<(), String> {

    // only track new entries to be inserted, first drop any dups by comparing against resolv.conf
    // then insert only new entries at the end (if any)
    let current_dns_entries = match get_dns_entries() {
        Some(cur) => cur,
        None => return Err("Couldn't read /etc/resolv.conf".to_string())
    };

    let mut new_entries = Vec::new();
    for entry in dns_entries {
        let mut found = false;
        for cur in &current_dns_entries {
            if cur == entry {
                found = true;
                break;
            }
        }
        if found == false {
            new_entries.push(entry);
        }
    }

    println!("Insert these {:?}", new_entries);

    //FIXME: Get all the 'namespace xxx.xxx.xxx.xxx' entries in a single vec and insert in one call.
    for entry in new_entries {
        let output = Command::new("sh")
            .arg("-c")
            .arg("echo nameserver ")
            .arg(entry.to_string())
            .arg(" >> /etc/resolv.conf")
            .output()
            .expect("failed to update resolv.conf");

        let out = output.stdout;
        if out.len() != 0 {
            return Err(String::from_utf8(out).unwrap());
        } 
    }
    Ok(())
}
