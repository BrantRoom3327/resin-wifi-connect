use std::process::Command;
use std::net::Ipv4Addr;
use regex::Regex;
use ExitResult;
use std::str::FromStr;
use iron::modifiers::Redirect;
use std::sync::mpsc::Sender;
use cookie::{CookieJar, Cookie, Key, SameSite};
use iron::{Request, Response, IronResult, status, IronError, Url};
use std::fs::OpenOptions;
use std::io::{Write, Read, Error, ErrorKind};
use std::io;
use serde_json;
use std::fs::File;
use std::fmt;
use iron::Set;
use hbs::Template;
use std::io::ErrorKind::InvalidData;
use server::{collect_set_config_options, collect_do_auth_options, get_kcf_runtime_data};
use num::FromPrimitive;

#[cfg(target_os = "linux")]
use linux::{get_gateway_for_adapter, get_netmask_for_adapter, get_dns_entries};

#[cfg(target_os = "macos")]
use macos::{get_gateway_for_adapter, get_netmask_for_adapter, get_dns_entries};

// this is an alias for public/config.hbs as that is handlebar style naming, but the extensions are stripped for runtime
pub const NO_HOTSPOT_SERVER_PORT: i32 = 8080;
pub const HTTP_PUBLIC: &str = "./ui"; //FIXME: Follow the config param
pub const CONFIG_TEMPLATE_NAME: &str = "config";
pub const STATUS_TEMPLATE_NAME: &str = "status";
//pub const WIFI_TEMPLATE_NAME: &str = "wifisettings";

//Files we read for configuration
pub const AUTH_FILE: &str = "auth.json";
pub const CFG_FILE: &str = "cfg.json";

//interface settings
pub const DEFAULT_COLLECTOR_ETHERNET_INTERFACE: &str = "eth0";
pub const DEFAULT_COLLECTOR_WIFI_INTERFACE: &str = "wlan0";
pub const DEFAULT_HOTSPOT_INTERFACE: &str = "wlan0";

// parsing of sd collector xml tags.
pub const PROMETHEUS_TAG_START: &str = "<PrometheusUrl>";
pub const PROMETHEUS_TAG_END: &str = "</PrometheusUrl>";
pub const PROXYSETTINGS_TAG_START: &str = "<ProxySettings>";
pub const PROXYSETTINGS_TAG_END: &str = "</ProxySettings>";
pub const SETTINGS_TAG_START: &str = "<Settings>";

// routes
pub const ROUTE_GET_CONFIG: &str = "/getconfig";
pub const ROUTE_SET_CONFIG: &str = "/setconfig";
pub const ROUTE_AUTH: &str = "/auth";
pub const ROUTE_SHOW_STATUS: &str = "/status";

// cookie for auth
pub const COOKIE_NAME: &str = "tastybiscuits";
pub const COOKIE_VALUE: &str = "lemonShortbread";
pub const COOKIE_EXPIRES_HOURS: i32 = 1;

enum_from_primitive! {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub enum NetworkCfgType {
        Ethernet_DHCP = 0,
        Ethernet_Static = 1,
        Wifi_DHCP = 2,
        Invalid = 3,
    }
}

//
// KCF Only Routes and functions, kept out of mainline files to avoid conflicts.
//
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub adapter_name: String,
    pub dhcp_enabled: bool,
    pub ip_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SmartDiagnosticsConfig {
    // cloud storage settings
    pub cloud_storage_enabled: bool,
    pub data_destination_url: String,

    // this is how the network supposted to be configured
    pub network_configuration_type: u8,  //at runtime a NetworkCfgType

    //ethernet static settings
    pub ethernet_ip_address: String,
    pub ethernet_subnet_mask: String,
    pub ethernet_gateway: String,
    pub ethernet_dns: Vec<String>,

    // proxy settings
    pub proxy_enabled: bool,
    pub proxy_login: String,
    pub proxy_password: String,
    pub proxy_gateway: String,
    pub proxy_gateway_port: u16,

    // master key used to generate cookie hashes.
    pub cookie_key: String,
    pub network_cfg_file: String, // generally will be /etc/network/interfaces but if you are testing it can be something else.
    pub collector_cfg_file: String, // The sdcollector.xml file that the sdcollector reads for proxy settings.
    pub collector_ethernet_interface: String,  //the name of the ethernet adapter to configure for the collector "eth0", "eth1" etc
    pub collector_wifi_interface: String,  //wlan0 or wlan1, etc
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetConfigOptionsFromPost {
    pub cloud_storage_enabled: bool,
    pub destination_address: String,
    pub network_configuration_type: u8,
    pub wifi_ssid: String,
    pub wifi_passphrase: String,
    pub ethernet_ip_address: String,
    pub ethernet_subnet_mask: String,
    pub ethernet_gateway: String,
    pub ethernet_dns: String,
    pub proxy_enabled: bool,
    pub proxy_login: String,
    pub proxy_password: String,
    pub proxy_gateway: String,
    pub proxy_gateway_port: u16,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct SDCollectoProxySettings {
    pub Enabled: bool,
    pub Server: String,
    pub Port: u16,
    pub UseDefaultCredentials: bool,
    pub User: String,
    pub Password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct KCFRuntimeData {
    pub http_server_address: String,
    pub collector_ethernet_interface: String, 
    pub collector_wifi_interface: String, 
}

impl fmt::Display for SmartDiagnosticsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// FIXME : lifetime of Result<String, io::Error>
pub fn create_cookie(cookie_key: &[u8]) -> String {
    if cookie_key.len() != 64 {
        panic!("create_cookie: The cookie master key is invalid at runtime!  This shouldn't happen!\n\n");
    }
    let key = Key::from_master(cookie_key);
    let mut jar = CookieJar::new();

    //setup the actual cookie
    //let mut cookie = Cookie::new(COOKIE_NAME, COOKIE_VALUE);
    let mut cookie = Cookie::build(COOKIE_NAME, COOKIE_VALUE)
       // .secure(true)
        .http_only(true)
        .finish();
  
    cookie.set_same_site(SameSite::Strict);
    
    //jar.private(&key).add(cookie);
    jar.add(cookie);
    jar.get(COOKIE_NAME).unwrap().to_string()
}

//TODO: Add cookie secure and database
pub fn validate_cookie<'a, 'b>(cookie_key: &'a [u8], cookie: &'b Cookie) -> bool {
    if cookie_key.len() != 64 {
        panic!("validate_cookie: The cookie master key is invalid at runtime!  This shouldn't happen!\n\n");
    }

    let (name, value) = cookie.name_value();

    let auth = if COOKIE_NAME == name && COOKIE_VALUE == value {
        true
    } else {
        false
    };

    auth
}

// instead of wiping the line, wipe the data between begin and end tags and insert new.
pub fn update_sd_collector_xml(cfg : &SmartDiagnosticsConfig) -> Result<(), io::Error> {

    let mut xml_data = match load_file_as_string(&cfg.collector_cfg_file) {
        Ok(xml) => xml,
        Err(e) => return Err(io::Error::new(InvalidData, format!("Could not load -> {}", cfg.collector_cfg_file))),
    };

    let prometheus_start = match find_offset_in_string(&xml_data, PROMETHEUS_TAG_START) {
        Some(start) => start + PROMETHEUS_TAG_START.to_string().len(),
        None => return Err(io::Error::new(InvalidData, format!("Could not load find {} tag in {}", PROMETHEUS_TAG_START.to_string(), cfg.collector_cfg_file))),
    };

    let prometheus_end = match find_offset_in_string(&xml_data, PROMETHEUS_TAG_END) {
        Some(end) => end,
        None => return Err(io::Error::new(InvalidData, format!("Could not load find {} tag in {}", PROMETHEUS_TAG_END.to_string(), cfg.collector_cfg_file))),
    };

    let drained_of_prometheus: String = xml_data.drain(prometheus_start..prometheus_end).collect();
    
    //now inject the data after the start tag.
    xml_data.insert_str(prometheus_start, &cfg.data_destination_url);

    let proxy_settings_start = match find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_START) {
        Some(start) => start + PROXYSETTINGS_TAG_START.to_string().len(),
        None => return Err(io::Error::new(InvalidData, format!("Could not load find {} tag in {}", PROXYSETTINGS_TAG_START.to_string(), cfg.collector_cfg_file))),
        //None => return,
    };

    let proxy_settings_end = match find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_END) {
        Some(end) => end,
        None => return Err(io::Error::new(InvalidData, format!("Could not load find {} tag in {}", PROXYSETTINGS_TAG_END.to_string(), cfg.collector_cfg_file))),
    };

    let drained_of_settings: String = xml_data.drain(proxy_settings_start..proxy_settings_end).collect();

    // now inject the data, starting at the end of the start tag
    let mut collector_settings = SDCollectoProxySettings {
        Enabled: cfg.proxy_enabled,
        Server: cfg.proxy_gateway.clone(),
        Port: cfg.proxy_gateway_port,
        UseDefaultCredentials: false,
        User: cfg.proxy_login.clone(),
        Password: cfg.proxy_password.clone(),
    };
    
    let collector_string = match serde_json::to_string(&collector_settings) {
        Ok(json) => json,
        Err(err) => panic!("Serialization didn't happen for collector settings!"),
    };

    xml_data.insert_str(proxy_settings_start, &collector_string);

    let file_ok = match write_file_contents(&xml_data, &cfg.collector_cfg_file) {
        Ok(yay) => yay,
        Err(e) => return Err(io::Error::new(InvalidData, format!("Failed to write to {} err {:?}", cfg.collector_cfg_file, e))),
    };

    Ok(())
}

// 
// KCF specific
//
pub fn set_config(req: &mut Request) -> IronResult<Response> {

    let options = match collect_set_config_options(req) {
        Ok(opt) => opt,
        Err(e) => return Err(e),
    };

    //
    // FIXME: Take a mutex.
    //
    let mut cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(cfg) => cfg,
        Err(err) => return Err(IronError::new(err, status::InternalServerError)),
    };

    // make sure the network configuration type gets validated here and type converted
    let network_configuration_type = match get_network_cfg_type(options.network_configuration_type) {
        Some(net) => net,
        None => {
            return Err(IronError::new(io::Error::new(InvalidData, format!("Invalid network configuration value")), status::InternalServerError));
        }
    };

    let mut validated_ethernet_settings = match validate_network_settings(
            &network_configuration_type, 
            &options.ethernet_ip_address, 
            &options.ethernet_subnet_mask, 
            &options.ethernet_gateway,
            &options.ethernet_dns)
    {
        Ok(settings) => settings,
        Err(err) => return Err(IronError::new(err, status::InternalServerError)),
    };

    // set the interface name in for the collector
    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    validated_ethernet_settings.adapter_name = kcf.collector_ethernet_interface;

    // wifi
    // TODO are these always correct in the ethernet enabled case.
    let wifi_settings = NetworkSettings {
        adapter_name: "wlan0".to_string(),
        dhcp_enabled: false,
        ip_address: "0.0.0.0".parse().unwrap(),
        gateway: "0.0.0.0".parse().unwrap(),
        netmask: "0.0.0.0".parse().unwrap(),
        dns: Vec::new(),
    };

    // setup ethernet adapter with new settings in config file.
    let network_configured = match configure_system_network_settings(&validated_ethernet_settings, &wifi_settings, &cfg.network_cfg_file) {
        Ok(settings) => settings,
        Err(e) => {
            println!("Unable to set network configuration");
            return Err(IronError::new(e, status::InternalServerError));
        }
    };

    //
    // update all the configuration data and write it all out
    //

    if options.cloud_storage_enabled {
        cfg.data_destination_url = options.destination_address;
    }

    if options.proxy_enabled {
        cfg.proxy_login = options.proxy_login;
        cfg.proxy_password = options.proxy_password;
        cfg.proxy_gateway = options.proxy_gateway;
        cfg.proxy_gateway_port = options.proxy_gateway_port;
    }

    // if we get this far, update the configuration, it was successful.
    cfg.proxy_enabled = options.proxy_enabled;
    cfg.cloud_storage_enabled = options.cloud_storage_enabled;
    cfg.network_configuration_type = options.network_configuration_type;

    // static settings
    cfg.ethernet_ip_address = options.ethernet_ip_address;
    cfg.ethernet_subnet_mask = options.ethernet_subnet_mask;
    cfg.ethernet_gateway = options.ethernet_gateway;
    cfg.ethernet_dns = [].to_vec();
    for ns in validated_ethernet_settings.dns {
        cfg.ethernet_dns.push(ns.to_string());
    }

    //
    // Update the sd collecto xml file
    //
    update_sd_collector_xml(&cfg);

    //
    // Write out the cfg file for the next server change.
    //
    
    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => { 
            return Err(IronError::new(err, status::InternalServerError));
        },
    };

    //let http_server_address = get_http_server_address(req).expect("Couldn't get request state at runtime");
    let show_status_route = "http://".to_string() + &kcf.http_server_address + ROUTE_SHOW_STATUS;

    // redirect back to login page on success
    let url = Url::parse(&show_status_route).unwrap();
    Ok(Response::with((status::Found, Redirect(url.clone()))))
}

pub fn get_config(req: &mut Request) -> IronResult<Response> {

    let headers = req.headers.to_string();
    let mut cookie_str = String::new();
    let cookie_prefix_len = "Cookie:".len();

    for line in headers.lines() {
        let offset = line.find("Cookie:").unwrap_or(headers.len());
        if offset != headers.len() {
            cookie_str = line.to_string();
            break;
        }
    }

    // FIXME: we need a page to send the user when things go wrong.  And display status 
    // with the normal layout as well as a link back to the login page.
    if cookie_str.len() < cookie_prefix_len {
        return Ok(Response::with((status::Unauthorized, "Not authorized.  Do you have cookies enabled for this site?")))
    }

    let c = Cookie::parse(&cookie_str[cookie_prefix_len..]).unwrap();

    // mutating this later, not saving it though
    let mut cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(cfg) => cfg,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    match validate_cookie(cfg.cookie_key.as_bytes(), &c) {
        true => (),
        false => {
            return Ok(Response::with((status::Unauthorized, "Invalid login.  Make sure you are authenticated to use this site.")))
        }
    }

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    let net_settings = match get_network_settings(&kcf.collector_ethernet_interface) {
        Some(settings) => settings,
        None => {
            println!("No network settings returned");
            NetworkSettings{
                            dhcp_enabled: false,
                            ip_address: "0.0.0.0".parse().unwrap(),
                            netmask: "0.0.0.0".parse().unwrap(),
                            gateway: "0.0.0.0".parse().unwrap(),
                            dns: Vec::new(),
                            adapter_name: "not_valid".to_string()}
        }
    };

    //NOTE: here overwrite the config we read from disk, we are not going to store it again.
    // the purpose is to inject the network settings we read from get_network_settings()
    cfg.ethernet_ip_address = format!("{}", net_settings.ip_address);
    cfg.ethernet_subnet_mask = format!("{}", net_settings.netmask);
    cfg.ethernet_gateway = format!("{}", net_settings.gateway);

    // convert ipv4addr to strings
    for entry in net_settings.dns {
        cfg.ethernet_dns.push(entry.to_string());
    }

    let mut resp = Response::new();
    resp.set_mut(Template::new(CONFIG_TEMPLATE_NAME, cfg)).set_mut(status::Ok);
    Ok(resp)
}

pub fn do_auth(req: &mut Request) -> IronResult<Response> {

    let http_post_auth = match collect_do_auth_options(req) {
        Ok(options) => options,
        Err(e) => return Err(e),
    };

    let creds = load_auth_file(AUTH_FILE).expect("Failed to load auth file");

    // can you compare entire structs?

    let auth_ok = if http_post_auth.username == creds.username && http_post_auth.password == creds.password 
        { true } 
    else
        { false };

    // the http server address is stored in the config file right now.
    let cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(config) => config,
        Err(config) => {
            println!("Failed to read/parse configuration file -> {} !\n", CFG_FILE);
            panic!("{:?}", config);
        }
    };

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    let get_config_route = "http://".to_string() + &kcf.http_server_address + ROUTE_GET_CONFIG;

    let url = Url::parse(&get_config_route).unwrap();

    let mut resp = match auth_ok {
        true => Response::with((status::Found, Redirect(url.clone()))),
        false => Response::with((status::Unauthorized, "Bad login"))
    };

    if auth_ok {
        let cookie_str = create_cookie(cfg.cookie_key.as_bytes());
        resp.headers.append_raw("Set-Cookie", cookie_str.into_bytes());
    }

    //println!("server response:\n{:?}", resp);
    Ok(resp)
}

pub fn get_status(req: &mut Request) -> IronResult<Response> {

    // create a live serde cfg object with all the status info
    let cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(config) => config,
        Err(config) => {
            println!("Failed to read/parse configuration file -> {} !\n", CFG_FILE);
            panic!("{:?}", config);
        }
    };

    let mut resp = Response::new();
    resp.set_mut(Template::new(STATUS_TEMPLATE_NAME, cfg)).set_mut(status::Ok);
    Ok(resp)
}

pub fn exit_with_error2(exit_tx: &Sender<ExitResult>, error: String) {
    println!("failed a sender command err"); 
}

pub fn get_network_settings(adapter_name: &str) -> Option<NetworkSettings> {
    let ip_address = match get_ip_for_adapter(adapter_name) {
        Some(ip_address) => ip_address,
        None => return None,
    };
    let netmask = match get_netmask_for_adapter(adapter_name) {
        Some(netmask) => netmask,
        None => return None,
    };
    let gateway = match get_gateway_for_adapter(adapter_name) {
        Some(gateway) => gateway,
        None => return None,
    };
    let dns = match get_dns_entries() {
        Some(dns) => dns,
        None => return None,
    };

    // FIXME: Can we determine if dhcp is already on this way?
    // we chould check for a running dhclient or dhcpcd on the sd_collector interface?
    Some(NetworkSettings{adapter_name: adapter_name.to_string(), 
        dhcp_enabled: false,
        ip_address: ip_address,
        netmask: netmask,
        gateway: gateway,
        dns: dns})
}

// get ip and netmask for the adapter
pub fn get_ip_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ifconfig")
        .arg(adapter)
        .output()
        .expect("failed to execute `ifconfig`");

    lazy_static! {
        static ref IP_RE: Regex =  Regex::new(r#"(?m)^.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in IP_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }

    println!("No IPAddress or gateway found for: {}", adapter);
    None
}

pub fn load_auth_file(file_path: &str) -> io::Result<Auth> {
    let mut data = String::new();
    let mut f = File::open(file_path)?;
    f.read_to_string(&mut data)?;
    let auth: Auth = serde_json::from_str(&data[..])?;
    Ok(auth)
}

pub fn load_diagnostics_config_file(filename: &str) -> io::Result<SmartDiagnosticsConfig> {
    let mut data = String::new();
    let mut f = File::open(filename)?;
    f.read_to_string(&mut data)?;
    let cfg: SmartDiagnosticsConfig = serde_json::from_str(&data[..])?;
    Ok(cfg)
}

pub fn load_file_as_string(file_path: &str) -> Result<String, io::Error> {
    let mut data = String::new();
    let mut f = File::open(file_path)?;
    f.read_to_string(&mut data)?;
    Ok(data)
}

pub fn write_file_contents(data: &str, file_path: &str) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).truncate(true).open(file_path)?;
    let bytes_out = f.write(data.as_bytes())?;
    let file_len = data.as_bytes().len();
    if bytes_out != file_len {
        let err_str = format!("Could not write all the data out, wrote {} of {} bytes to {}", bytes_out, file_len, file_path);
        return Err(io::Error::new(InvalidData, err_str))
    }
    Ok(())
}

pub fn write_diagnostics_config(config: &SmartDiagnosticsConfig) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).truncate(true).open(CFG_FILE)?;
    let data = match serde_json::to_string(&config) {
        Ok(computer) => computer,
        Err(e) => return Err(io::Error::new(InvalidData, e)),
    };
    let bytes_out = f.write(data.as_bytes())?;
    Ok(())
}

pub fn find_offset_in_string(haystack: &str, needle: &str) -> Option<usize> {
    let haystack_len = haystack.len(); 
    let offset = haystack.find(needle).unwrap_or(haystack_len);
    if offset != haystack_len {
        return Some(offset);
    } else {
        return None;
    }
}

fn validate_network_settings(network_configuration_type: &NetworkCfgType, ip_address: &str, netmask: &str, gateway: &str, dns: &str)
    -> Result<NetworkSettings, io::Error> 
 {
     let adapter_name = "".to_string();

    // we now have network_configuration_type:
    // * Eth0 static
    // * Eth0 dhcp
    // * wifi dhcp

    if network_configuration_type == &NetworkCfgType::Ethernet_DHCP {
        // return invalid static info, we are using dhcp
        return Ok(NetworkSettings{ 
             adapter_name: adapter_name, 
             dhcp_enabled: true,
             ip_address: "0.0.0.0".parse().unwrap(),
             netmask: "0.0.0.0".parse().unwrap(),
             gateway: "0.0.0.0".parse().unwrap(),
             dns: Vec::new(),
         });

    } else if network_configuration_type == &NetworkCfgType::Ethernet_Static {

        let valid_ip_address = match Ipv4Addr::from_str(&ip_address) {
            Ok(eth) => eth,
            Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to parse ip address!")),
        };
    
        let valid_netmask = match Ipv4Addr::from_str(&netmask) {
            Ok(nm) => nm,
            Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to parse subnet mask!")),
        };
    
        let valid_gateway = match Ipv4Addr::from_str(&gateway) {
            Ok(gw) => gw,
            Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to parse gateway!")),
        };
    
        let vec_dns: Vec<&str> = dns.split(',').collect();
        let mut valid_dns_entries = Vec::new();
        for v in vec_dns {
            let trimmed_ip = v.trim();
            match trimmed_ip.parse::<Ipv4Addr>() {
                Ok(entry) => valid_dns_entries.push(entry),
                Err(e) => return Err(Error::new(ErrorKind::Other, "Invalid DNS entry!")),
            };
        }
        valid_dns_entries.dedup();

        // return static setup
        return Ok(NetworkSettings{
            adapter_name: adapter_name,
            dhcp_enabled: false,
            ip_address: valid_ip_address, 
            netmask: valid_netmask,
            gateway: valid_gateway, 
            dns: valid_dns_entries});

    } else if network_configuration_type == &NetworkCfgType::Wifi_DHCP {
        // here we also want invalid ethernet settings but we want
        // store the last connected SSID for future use when switching back and forth for the user.

        //currently there is no info here, 
        return Ok(NetworkSettings{ 
             adapter_name: adapter_name, 
             dhcp_enabled: true,
             ip_address: "0.0.0.0".parse().unwrap(),
             netmask: "0.0.0.0".parse().unwrap(),
             gateway: "0.0.0.0".parse().unwrap(),
             dns: Vec::new(),
         });
    } else {
        return Err(Error::new(ErrorKind::Other, "validate_network_settings: Invalid Network configuration type!"));
    }
}

// configure all the network settings in one go.
// wifi and ethernet.
fn configure_system_network_settings(ethernet_settings: &NetworkSettings, wifi_settings: &NetworkSettings, file_path: &str) 
    -> Result<(), io::Error>
{
    let input_config_data = match load_file_as_string(file_path) {
        Ok(data) => data,
         Err(e) => {
            println!("Could not load config file {}", file_path);
            return Err(Error::new(ErrorKind::Other, "configure_system_network_settings(): could not load the file!"));
         }
    };

    let mut output_config_data = String::new();

    //keep everything with a #comment line and write it to the output.
    for line in input_config_data.lines() {
        let offset = line.find("#").unwrap_or(input_config_data.len());
        if offset == 0 { //starts with a #comment
            let saved_line = line.to_string() + "\n";
            output_config_data.push_str(&saved_line);
        }
    }

    // loopback
    output_config_data.push_str("\nauto lo\n");
    output_config_data.push_str("iface lo inet loopback\n\n");

    // order of configuraton
    // if wifi_settings.dhcp_enabled is on, enable wifi on wlan adapter interface
    // disable the ethernet adapter (shouldn't be used for sd collector)
    // else if eithernet dhcp is on, don't use wifi
    // else ethernet static settings should be applied, and also don't use wifi

    // Consider turning the strings into packages to drop into the format! macro

    if wifi_settings.dhcp_enabled {
        // enable dhcp for wifi adapter
        output_config_data.push_str(&format!("auto {}\n", wifi_settings.adapter_name));
        output_config_data.push_str(&format!("allow-hotplpug {}\n", wifi_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} inet dhcp\n", wifi_settings.adapter_name));
        output_config_data.push_str("wpa-conf /etc/wpa_supplicant/wpa_suppplicant.conf\n");
        output_config_data.push_str("iface default inet dhcp\n\n");

        // disable ethernet here
        output_config_data.push_str(&format!("auto {}\n", ethernet_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} down\n\n", ethernet_settings.adapter_name));

    } else if ethernet_settings.dhcp_enabled {

        //enable dhcp for ethernet adapter
        output_config_data.push_str(&format!("auto {}\n", ethernet_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} inet dhcp\n\n", ethernet_settings.adapter_name));

        // disable wifi here
        output_config_data.push_str(&format!("auto {}\n", wifi_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} down\n\n", wifi_settings.adapter_name));

    } else {

        // enable static addressing for adapter
        output_config_data.push_str(&format!("auto {}\n", ethernet_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} inet static\n", ethernet_settings.adapter_name));
        output_config_data.push_str(&format!("address {}\n", ethernet_settings.ip_address.to_string()));
        output_config_data.push_str(&format!("netmask {}\n", ethernet_settings.netmask.to_string()));
        output_config_data.push_str(&format!("gateway {}\n", ethernet_settings.gateway.to_string()));

        output_config_data.push_str("dns-nameservers "); 
        let dns_len = ethernet_settings.dns.len();
        let mut index = 0;
        for ns in &ethernet_settings.dns {
            output_config_data.push_str(&format!("{}", ethernet_settings.gateway.to_string()));
            if index != (dns_len - 1) {
                // if we are not on the last entry add a ,
                output_config_data.push_str(", ");
            }
            index = index+1;
        }
        output_config_data.push_str("\n\n");

        //turn off wifi
        output_config_data.push_str(&format!("auto {}\n", wifi_settings.adapter_name));
        output_config_data.push_str(&format!("iface {} down\n\n", wifi_settings.adapter_name));
    }

    println!("Config we would write\n{}", output_config_data);

    let wrote_file = match write_file_contents(&output_config_data, file_path) {
        Ok(wrote) => wrote,
        Err(e) => {
            println!("Failed to write network configuration file {} err -> {:?}\n", file_path, e);
            return Err(e);
        }
    };

    Ok(())
}

pub fn get_network_cfg_type(value: u8) -> Option<NetworkCfgType> {
     let network_configuration_type = match NetworkCfgType::from_u8(value) {
        Some(val) => val,
        None => {
            println!("invalid form value for network cfg type!");
            return None;
        }
    };

    Some(network_configuration_type)
}