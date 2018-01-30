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
use std::io::{Write, Read};
use std::io;
use serde_json;
use std::fs::File;
use std::fmt;
use std::fmt::Error;
use iron::Set;
use hbs::Template;
use std::io::ErrorKind::InvalidData;
use server::{collect_set_config_options, collect_do_auth_options, get_sd_collector_ethernet_interface, get_http_server_address};

#[cfg(target_os = "linux")]
use linux::{get_gateway_for_adapter, get_netmask_for_adapter, get_dns_entries};

#[cfg(target_os = "macos")]
use macos::{get_gateway_for_adapter, get_netmask_for_adapter, get_dns_entries};

// this is an alias for public/config.hbs as that is handlebar style naming, but the extensions are stripped for runtime
pub const NO_HOTSPOT_SERVER_PORT: i32 = 8080;
pub const HTTP_PUBLIC: &str = "./ui"; //FIXME: Follow the config param
pub const CONFIG_TEMPLATE_NAME: &str = "config";
pub const STATUS_TEMPLATE_NAME: &str = "status";
pub const WIFI_TEMPLATE_NAME: &str = "wifisettings";

//required config and auth files for the server to validate connections and store persistent data.
pub const AUTH_FILE: &str = "auth.json";
pub const CFG_FILE: &str = "cfg.json";

// just using a temp file for now before live settings.
pub const NETWORK_INTERFACES_CFG: &str = "etc_network_interfaces";

//sd collector info/settings
pub const DEFAULT_SD_COLLECTOR_INTERFACE: &str = "eth0";
pub const SD_COLLECTOR_XML_FILE: &str = "collectorsettings.xml";
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

    //replace with a NetworkSettings?
    pub ethernet_dhcp_enabled: bool,
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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetConfigOptionsFromPost {
    pub cloud_storage_enabled: bool,
    pub destination_address: String,
    pub ethernet_dhcp_enabled: bool,
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
pub struct sd_collector_proxy_settings {
    pub Enabled: bool,
    pub Server: String,
    pub Port: u16,
    pub UseDefaultCredentials: bool,
    pub User: String,
    pub Password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Auth{
    pub username: String,
    pub password: String,
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
    //println!("Validate -> name {} cookie value {}", name, value);

    let auth = if COOKIE_NAME == name && COOKIE_VALUE == value {
        true
    } else {
        false
    };

    auth
}

// instead of wiping the line, wipe the data between begin and end tags and insert new.
// FIXME: Add some more error checking
pub fn update_sd_collector_xml(cfg : &SmartDiagnosticsConfig, file_path: &str) {

    let mut xml_data = match load_file_as_string(file_path) {
        Ok(xml) => xml,
        Err(e) => return,
    };

    let prometheus_start = match find_offset_in_string(&xml_data, PROMETHEUS_TAG_START) {
        Some(start) => start + PROMETHEUS_TAG_START.to_string().len(),
        None => return,
    };

    let prometheus_end = match find_offset_in_string(&xml_data, PROMETHEUS_TAG_END) {
        Some(end) => end,
        None => return,
    };

    let drained_of_prometheus: String = xml_data.drain(prometheus_start..prometheus_end).collect();
    
    //now inject the data after the start tag.
    xml_data.insert_str(prometheus_start, &cfg.data_destination_url);

    let proxy_settings_start = match find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_START) {
        Some(start) => start + PROXYSETTINGS_TAG_START.to_string().len(),
        None => return,
    };

    let proxy_settings_end = match find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_END) {
        Some(end) => end,
        None => return,
    };

    let drained_of_settings: String = xml_data.drain(proxy_settings_start..proxy_settings_end).collect();

    // now inject the data, starting at the end of the start tag
    let mut collector_settings = sd_collector_proxy_settings {
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
    //println!("xml at end\n{}", xml_data);

    write_file_contents(&xml_data, file_path);
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
    
    let sd_collector_interface = get_sd_collector_ethernet_interface(req).expect("Couldn't get request state at runtime!");

    let mut validated_ethernet_settings = match validate_network_settings(
            options.ethernet_dhcp_enabled, &options.ethernet_ip_address, 
            &options.ethernet_subnet_mask, &options.ethernet_gateway, &options.ethernet_dns)
    {
        Ok(settings) => settings,
        Err(e) => return Ok(Response::with((status::InternalServerError, e))),
    };

    // set the interface name in for the collector
    validated_ethernet_settings.adapter_name = sd_collector_interface;

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
    let network_configured = match configure_system_network_settings(&validated_ethernet_settings, &wifi_settings) {
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
    cfg.ethernet_dhcp_enabled = options.ethernet_dhcp_enabled;
    cfg.ethernet_ip_address = options.ethernet_ip_address;
    cfg.ethernet_subnet_mask = options.ethernet_subnet_mask;
    cfg.ethernet_gateway = options.ethernet_gateway;

    // convert to strings for assignment
    cfg.ethernet_dns = [].to_vec();
    for ns in validated_ethernet_settings.dns {
        cfg.ethernet_dns.push(ns.to_string());
    }

    //
    // Update the sd collecto xml file
    //
    update_sd_collector_xml(&cfg, SD_COLLECTOR_XML_FILE);

    //
    // Write out the cfg file for the next server change.
    //
    
    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => { 
            return Err(IronError::new(err, status::InternalServerError));
        },
    };

    let http_server_address = get_http_server_address(req).expect("Couldn't get request state at runtime");
    let show_status_route = "http://".to_string() + &http_server_address + ROUTE_SHOW_STATUS;

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

    let sd_collector_interface = get_sd_collector_ethernet_interface(req).expect("Couldn't get request state at runtime!");
    let net_settings = match get_network_settings(&sd_collector_interface) {
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

    let http_server_address = get_http_server_address(req).expect("Couldn't get request state at runtime");
    let get_config_route = "http://".to_string() + &http_server_address + ROUTE_GET_CONFIG;

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

pub fn load_file_as_string(file_path: &str) -> io::Result<String> {
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

pub fn write_diagnostics_config(config: &SmartDiagnosticsConfig) -> Result<(), io::Error> {
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

fn validate_network_settings(dhcp_enabled: bool, ip_address: &str, netmask: &str, gateway: &str, dns: &str)
    -> Result<NetworkSettings, String> 
 {
     let adapter_name = "".to_string();
     if dhcp_enabled {
         return Ok(NetworkSettings{ 
             adapter_name: adapter_name, 
             dhcp_enabled: true,
             ip_address: "0.0.0.0".parse().unwrap(),
             netmask: "0.0.0.0".parse().unwrap(),
             gateway: "0.0.0.0".parse().unwrap(),
             dns: Vec::new(),
         });
     } 

    //static
    let valid_ip_address = match Ipv4Addr::from_str(&ip_address) {
        Ok(eth) => eth,
        _ => return Err("Bad ethernet address".to_string())
    };

    let valid_netmask = match Ipv4Addr::from_str(&netmask) {
        Ok(eth) => eth,
        _ => return Err("Bad subnet mask".to_string())
    };

    let valid_gateway = match Ipv4Addr::from_str(&gateway) {
        Ok(eth) => eth,
        _ => return Err("Bad gateway".to_string())
    };

    let vec_dns: Vec<&str> = dns.split(',').collect();
    let mut valid_dns_entries = Vec::new();
    for v in vec_dns {
        let trimmed_ip = v.trim();
        match trimmed_ip.parse::<Ipv4Addr>() {
            Ok(entry) => valid_dns_entries.push(entry),
            Err(e) => {
                let err_str = format!("Invalid dns entry {} {:?}", v, e);
                return Err(err_str);
            }
        };
    }
    valid_dns_entries.dedup();

    // return static setup
    let settings = NetworkSettings{adapter_name: adapter_name,
        dhcp_enabled: false,
        ip_address: valid_ip_address, 
        netmask: valid_netmask,
        gateway: valid_gateway, 
        dns: valid_dns_entries};

    Ok(settings)
}

// configure all the network settings in one go.
// wifi and ethernet.
fn configure_system_network_settings(ethernet_settings: &NetworkSettings, wifi_settings: &NetworkSettings) -> io::Result<bool>
{
    let mut etc_network_interfaces = match load_file_as_string(NETWORK_INTERFACES_CFG) {
        Ok(data) => data,
        Err(e) => { return Err(e) }
    };

    //keep everything with a #comment line and write it to the output.

    // write ethernet settings


    // write wifi settings


    // write out the file
    Ok(true)
}