#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::process::Command;
use std::net::Ipv4Addr;
use regex::Regex;
use std::str::FromStr;
use iron::modifiers::Redirect;
use cookie::{Cookie, CookieJar, SameSite};
use iron::{status, IronError, IronResult, Request, Response, Url};
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Write};
use std::io;
use serde_json;
use std::fs::File;
use std::fmt;
use iron::Set;
use hbs::Template;
use std::io::ErrorKind::InvalidData;
use server::{collect_do_auth_options, collect_set_config_options, get_kcf_runtime_data, inject_to_runtime};
use num::FromPrimitive;
use handlebars::Handlebars;
use serde_json::Value;

#[cfg(target_os = "linux")]
use linux::{get_dns_entries, get_gateway_for_adapter, get_netmask_for_adapter};

#[cfg(target_os = "macos")]
use macos::{get_dns_entries, get_gateway_for_adapter, get_netmask_for_adapter};

pub const NO_HOTSPOT_SERVER_PORT: i32 = 8080;

//templates for network configurations written to disk
pub const TEMPLATE_DIR: &str = "/templates/";

//TODO: Look for these files on startup.
// templates for ethernet configuration file writes
pub const ETHERNET_STATIC_SETTINGS_TEMPLATE: &str = "./ui/templates/ethernet-setup-static.hbs";
pub const ETHERNET_DISABLE_TEMPLATE: &str = "./ui/templates/ethernet-disable.hbs";
pub const ETHERNET_DHCP_ENABLE_TEMPLATE: &str = "./ui/templates/ethernet-dhcp-enable.hbs";
pub const WIFI_DHCP_ENABLE_TEMPLATE: &str = "./ui/templates/wifi-dhcp-enable.hbs";
pub const WIFI_DISABLE_TEMPLATE: &str = "./ui/templates/wifi-disable.hbs";

//http templates for webpages
pub const HTTP_CONFIG_TEMPLATE: &str = "config";
pub const HTTP_STATUS_TEMPLATE: &str = "status";

//defaults for config not given on the commandline
pub const DEFAULT_HOTSPOT_INTERFACE: &str = "wlan0";
pub const DEFAULT_CONFIG_FILE_PATH: &str = "./data/cfg.json";
pub const DEFAULT_AUTH_FILE_PATH: &str = "./data/auth.json";

// parsing of sd collector xml tags.
// TODO: Consider Pest for parsing instead of hand parsing the XML file.
pub const PROMETHEUS_TAG_START: &str = "<PrometheusUrl>";
pub const PROMETHEUS_TAG_END: &str = "</PrometheusUrl>";
pub const PROXYSETTINGS_TAG_START: &str = "<ProxySettings>";
pub const PROXYSETTINGS_TAG_END: &str = "</ProxySettings>";

// routes
pub const ROUTE_GET_CONFIG: &str = "/getconfig";
pub const ROUTE_SET_CONFIG: &str = "/setconfig";
pub const ROUTE_AUTH: &str = "/auth";
pub const ROUTE_SHOW_STATUS: &str = "/status";

// cookie for auth
pub const COOKIE_NAME: &str = "tastybiscuits";
pub const COOKIE_VALUE: &str = "lemonShortbread";

enum_from_primitive! {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub enum NetworkCfgType {
        Ethernet_Static = 0,
        Ethernet_DHCP = 1,
        Wifi_DHCP = 2,
        Invalid = 3,
    }
}

//merge serde_json::Value's together and return the mutated input
fn merge(a: &mut Value, b: Value) {
    match (a, b) {
        (a @ &mut Value::Object(_), Value::Object(b)) => {
            let a = a.as_object_mut().unwrap();
            for (k, v) in b {
                merge(a.entry(k).or_insert(Value::Null), v);
            }
        },
        (a, b) => *a = b,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkSettings {
    pub adapter_name: String,
    pub dhcp_enabled: bool,
    pub ip_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

impl NetworkSettings {
    pub fn new(adapter_name: String) -> NetworkSettings {
        NetworkSettings {
            adapter_name,
            dhcp_enabled: false,
            ip_address: "0.0.0.0".parse().unwrap(),
            netmask: "0.0.0.0".parse().unwrap(),
            gateway: "0.0.0.0".parse().unwrap(),
            dns: Vec::new(),
        }
    }
    // used to grab the static streaming nic settings that never change.  For now.
    pub fn get_static_streaming_settings(adapter_name: String) -> NetworkSettings {
        NetworkSettings {
            adapter_name,
            dhcp_enabled: false,
            ip_address: "192.168.151.100".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            gateway: "192.168.151.100".parse().unwrap(),
            dns: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WifiAPSettings {
    pub adapter_name: String,
    pub ssid: String,
    pub psk: String,
}

impl WifiAPSettings {
    pub fn new() -> WifiAPSettings {
        WifiAPSettings {
            adapter_name: String::new(),
            ssid: String::new(),
            psk: String::new(),
        }
    }
    /*
    pub fn init(adapter_name: String, ssid: String, psk: String) -> WifiAPSettings {
        WifiAPSettings {
            adapter_name,
            ssid,
            psk,
        }
    }*/
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterfaces {
    pub collector_ethernet: String, //ethernet for upstream to cloud.
    pub collector_wifi: String,     //wifi for upstream to cloud
    pub static_streaming_ethernet: String, //unchanging static addressed interface for streaming
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputFiles {
    pub collector_ethernet: String, //conf file for the collector_ethernet interface
    pub collector_wifi: String,     //conf file for the collector_wifi interface
    pub static_streaming_ethernet: String, //conf file for the static_streaming_ethernet interface
    pub collector_xml_file: String, //conf file read by collector
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxySettings {
    pub enabled: bool,
    pub login: String,
    pub password: String,
    pub gateway: String,
    pub gateway_port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SmartDiagnosticsConfig {
    // cloud storage settings
    pub cloud_storage_enabled: bool,
    pub data_destination_url: String,
    pub network_configuration_type: u8, //at runtime a NetworkCfgType
    pub cookie_key: String,             // master key used to generate cookie hashes.

    pub proxy: ProxySettings,
    pub network_interfaces: NetworkInterfaces,
    pub output_files: OutputFiles,
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
    pub proxy: ProxySettings,
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

#[derive(Deserialize, PartialEq, PartialOrd, Debug, Clone)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeData {
    pub http_server_address: String,
    //config
    pub config_file_path: String,
    pub config_data: SmartDiagnosticsConfig,
    //auth
    pub auth_file_path: String,
    pub auth_data: Auth,

    //data sent from client, used for display
    pub ethernet_static_network_settings: NetworkSettings, //used to store ethernet static settings as needed for templating
    pub wifi_dhcp_network_settings: WifiAPSettings,
}

impl fmt::Display for SmartDiagnosticsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn create_cookie(cookie_key: &[u8]) -> String {
    if cookie_key.len() != 64 {
        panic!("create_cookie: The cookie master key is invalid at runtime!\n\n");
    }
    //let key = Key::from_master(cookie_key);
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
pub fn validate_cookie<'a, 'b>(cookie_key: &'a [u8], cookie: &'b Cookie) -> Result<(), io::Error> {
    if cookie_key.len() != 64 {
        panic!("validate_cookie: The cookie master key is invalid at runtime!\n\n");
    }

    let (name, value) = cookie.name_value();

    if COOKIE_NAME == name && COOKIE_VALUE == value {
        return Ok(());
    } else {
        return Err(io::Error::new(InvalidData, format!("Cookie is not valid!")));
    };
}

// instead of wiping the line, wipe the data between begin and end tags and insert new.
pub fn update_sd_collector_xml(cfg: &SmartDiagnosticsConfig) -> Result<(), io::Error>
{
    let mut xml_data = load_file_as_string(&cfg.output_files.collector_xml_file)?;
    
    // find <PrometheusURL>
    let mut prometheus_start = find_offset_in_string(&xml_data, PROMETHEUS_TAG_START)?;
    prometheus_start += PROMETHEUS_TAG_START.len(); //skip to end of string
    let prometheus_end = find_offset_in_string(&xml_data, PROMETHEUS_TAG_END)?;

    //delete data inbetween tags
    let _: String = xml_data.drain(prometheus_start..prometheus_end).collect();

    //now inject the data after the start tag.
    xml_data.insert_str(prometheus_start, &cfg.data_destination_url);

    // find <ProxySettings>
    let mut proxy_settings_start = find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_START)?;
    proxy_settings_start += PROXYSETTINGS_TAG_START.len();
    let proxy_settings_end = find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_END)?;

    //delete data between tags
    let _drained_of_settings: String = xml_data
        .drain(proxy_settings_start..proxy_settings_end)
        .collect();

    // now inject the data, starting at the end of the start tag
    let collector_settings = SDCollectoProxySettings {
        Enabled: cfg.proxy.enabled,
        Server: cfg.proxy.gateway.clone(),
        Port: cfg.proxy.gateway_port,
        UseDefaultCredentials: false,
        User: cfg.proxy.login.clone(),
        Password: cfg.proxy.password.clone(),
    };

    let collector_string = match serde_json::to_string(&collector_settings) {
        Ok(json) => json,
        Err(e) => {
            return Err(io::Error::new(
                InvalidData,
                format!(
                    "Failed to serialize data to xml! file {} err {}",
                    cfg.output_files.collector_xml_file, e
                ),
            ))
        },
    };

    //inject json into xml file
    xml_data.insert_str(proxy_settings_start, &collector_string);

    //write the altered file
    write_file_contents(&xml_data, &cfg.output_files.collector_xml_file, true)?;
        
    Ok(())
}

pub fn http_route_set_config(req: &mut Request) -> IronResult<Response> {

    let options = collect_set_config_options(req)?;

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");

    //create a mutable instance of config data, we will edit it and write it back out.
    let mut config_data = kcf.config_data.clone();

    // make sure the network configuration type gets validated here and type converted
    let network_configuration_type = match get_network_cfg_type(options.network_configuration_type) {
        Some(net) => net,
        None => {
            return Err(IronError::new(
                io::Error::new(InvalidData, format!("Invalid network configuration value")),
                status::InternalServerError,
            ))
        },
    };

    let validated_ethernet_settings = match validate_network_settings(
        &network_configuration_type,
        &config_data.network_interfaces.collector_ethernet,
        &options.ethernet_ip_address,
        &options.ethernet_subnet_mask,
        &options.ethernet_gateway,
        &options.ethernet_dns,
    ) {
        Ok(settings) => settings,
        Err(err) => {
            debug!("Network settings validation failed!");
            return Err(IronError::new(err, status::InternalServerError));
        },
    };

    let static_streaming_settings = NetworkSettings::get_static_streaming_settings(
            config_data.network_interfaces.static_streaming_ethernet.clone());

    let wifi_settings = NetworkSettings::new(config_data.network_interfaces.collector_wifi.clone());

    // setup ethernet adapter with new settings in config file.
    match configure_system_network_settings(
        &validated_ethernet_settings,
        &wifi_settings,
        &static_streaming_settings,
        &config_data.output_files.collector_ethernet,
        &config_data.output_files.collector_wifi,
        &config_data.output_files.static_streaming_ethernet,)
    {
        Ok(()) => (),
        Err(e) => {
            debug!(" Error -> {:?}", e);
            return Err(IronError::new(e, status::InternalServerError));
        },
    }

    //
    // update all the configuration data and write it all out
    //

    if options.cloud_storage_enabled {
        config_data.data_destination_url = options.destination_address;
    }

    if options.proxy.enabled {
        config_data.proxy = options.proxy.clone();
    }

    // if we get this far, update the configuration, it was successful.
    config_data.cloud_storage_enabled = options.cloud_storage_enabled;
    config_data.network_configuration_type = options.network_configuration_type;
    config_data.proxy.enabled = options.proxy.enabled;

    //
    // inject the new static ethernet settings into runtime data only if we need it (ethernet
    // static selected)
    //
    match network_configuration_type  {
        NetworkCfgType::Ethernet_Static => inject_to_runtime(req, validated_ethernet_settings)?,
        //FIXME: add cfg for wifi settings.
        _ => (),
    };

    //
    // Update the sd collector xml file
    //
    if update_sd_collector_xml(&config_data).is_err() {
        return Err(IronError::new(
            io::Error::new(InvalidData, format!("Unable to update collector XML file!")),
            status::InternalServerError,
        ));
    }

    //
    // Write out the config_data file for the next server change.
    //
    let _status = match write_diagnostics_config(&config_data, &kcf.config_file_path) {
        Ok(s) => s,
        Err(err) => return Err(IronError::new(err, status::InternalServerError)),
    };

    let show_status_route = "http://".to_string() + &kcf.http_server_address + ROUTE_SHOW_STATUS;

    // redirect back to login page on success
    let url = Url::parse(&show_status_route).unwrap();
    Ok(Response::with((status::Found, Redirect(url.clone()))))
}

pub fn http_route_get_config(req: &mut Request) -> IronResult<Response> {
    let headers = req.headers.to_string();
    let mut cookie_str = String::new();
    let COOKIE_TAG = "Cookie:";

    for line in headers.lines() {
        let offset = line.find(COOKIE_TAG).unwrap_or(headers.len());
        if offset != headers.len() {
            cookie_str = line.to_string();
            break;
        }
    }

    // FIXME: we need a page to send the user when things go wrong.  And display status
    // with the normal layout as well as a link back to the login page.
    if cookie_str.len() < COOKIE_TAG.len() {
        return Ok(Response::with((
            status::Unauthorized,
            "Not authorized.  Do you have cookies enabled for this site?",
        )));
    }

    let c = Cookie::parse(&cookie_str[COOKIE_TAG.len()..]).unwrap();

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");

    match validate_cookie(kcf.config_data.cookie_key.as_bytes(), &c) {
        Ok(()) => (),
        Err(err) => return Err(IronError::new(err, status::InternalServerError)),
    }

    let net_settings =
        match get_network_settings(&kcf.config_data.network_interfaces.collector_ethernet) {
            Some(settings) => settings,
            None => {
                return Ok(Response::with((
                    status::Unauthorized,
                    "Failed to acquire network settings from ethernet adapter.",
                )))
            },
        };

    //inject the live network settings into the configuration we have stored and use
    //the merged output for the template render.
    let mut cfg_json = json!(kcf.config_data);
    merge(&mut cfg_json, json!(net_settings));

    let mut resp = Response::new();
    resp.set_mut(Template::new(HTTP_CONFIG_TEMPLATE, cfg_json))
        .set_mut(status::Ok);
    Ok(resp)
}

pub fn http_route_do_auth(req: &mut Request) -> IronResult<Response> {
    let http_post_auth = match collect_do_auth_options(req) {
        Ok(options) => options,
        Err(e) => return Err(e),
    };

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");

    // diff auth file creds with those passed via http post. Comparing two of 'struct Auth'
    let auth_ok = http_post_auth == kcf.auth_data;

    let get_config_route = "http://".to_string() + &kcf.http_server_address + ROUTE_GET_CONFIG;

    let url = Url::parse(&get_config_route).unwrap();

    let mut resp = match auth_ok {
        true => Response::with((status::Found, Redirect(url.clone()))),
        false => return Ok(Response::with((status::Unauthorized, "Bad login"))),
    };

    //success auth at this point
    let cookie_str = create_cookie(kcf.config_data.cookie_key.as_bytes());
    resp.headers.append_raw("Set-Cookie", cookie_str.into_bytes());
    //println!("server response:\n{:?}", resp);
    Ok(resp)
}

pub fn http_route_get_status(req: &mut Request) -> IronResult<Response> {
    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");

    // re-read the configuration here, it probably changed.  The kcf data will be stale at this
    // point.  We could consider repopulating the data if we needed to but do it in set_config instead.
    let data_from_cfg_file = match load_diagnostics_config_file(&kcf.config_file_path) {
        Ok(data) => data,
        Err(e) => panic!(
            "Failed to read configuration file -> {}! e={:?}\n",
            kcf.config_file_path, e
        ),
    };

    // merge in the network settings that were sent to the server but are not stored
    // in the cfg file.
    let mut cfg_json = json!(data_from_cfg_file);

    //only merge in the template data we need based on configuration type.
    let net_cfg = get_network_cfg_type(kcf.config_data.network_configuration_type);
    match net_cfg {
        Some(NetworkCfgType::Ethernet_Static) => 
            merge(&mut cfg_json, json!(kcf.ethernet_static_network_settings)),
        Some(NetworkCfgType::Wifi_DHCP) => 
            merge(&mut cfg_json, json!(kcf.wifi_dhcp_network_settings)),
        _ => merge(&mut cfg_json, json!({})), //don't merge in anything
    }

    let mut resp = Response::new();
    resp.set_mut(Template::new(HTTP_STATUS_TEMPLATE, cfg_json))
        .set_mut(status::Ok);
    Ok(resp)
}

pub fn get_network_settings(adapter_name: &str) -> Option<NetworkSettings> {
    let ip_address = get_ip_for_adapter(adapter_name)?;
    let netmask = get_netmask_for_adapter(adapter_name)?;
    let gateway = get_gateway_for_adapter(adapter_name)?;
    let dns = get_dns_entries()?;

    Some(NetworkSettings {
        adapter_name: adapter_name.to_string(),
        dhcp_enabled: false,
        ip_address,
        netmask,
        gateway,
        dns,
    })
}

// get ip and netmask for the adapter
pub fn get_ip_for_adapter(adapter: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ifconfig")
        .arg(adapter)
        .output()
        .expect("failed to execute `ifconfig`");

    lazy_static! {
        static ref IP_RE: Regex =  Regex::new(
            r#"(?m)^.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*$"#).unwrap();
    }

    let stdout = String::from_utf8(output.stdout).unwrap();
    for cap in IP_RE.captures_iter(&stdout) {
        if let &Ok(addr) = &cap[2].parse::<Ipv4Addr>() {
            return Some(addr);
        }
    }

    // This is to handle the case that ethernet is not plugged in or up
    // we don't want to fail, we would like to display an invalid value to the user.
    debug!("No IPAddress or gateway found for: {}", adapter);
    Some(Ipv4Addr::new(0,0,0,0))
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

pub fn write_file_contents(data: &str, file_path: &str, create_new_file: bool) -> Result<(), io::Error> {
    let mut f = if create_new_file {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(file_path)?
    } else {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(file_path)?
    };

    let bytes_out = f.write(data.as_bytes())?;
    let file_len = data.as_bytes().len();
    if bytes_out != file_len {
        let err_str = format!(
            "Could not write all the data out, wrote {} of {} bytes to {}",
            bytes_out, file_len, file_path
        );
        return Err(io::Error::new(InvalidData, err_str));
    }
    Ok(())
}

pub fn write_diagnostics_config(config: &SmartDiagnosticsConfig, file_path: &str) -> Result<(), io::Error>
{
    let data = serde_json::to_string_pretty(&config)?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(file_path)?;
    f.write(data.as_bytes())?;

    Ok(())
}

pub fn find_offset_in_string(haystack: &str, needle: &str) -> Result<usize, io::Error> {
    let haystack_len = haystack.len();
    let offset = haystack.find(needle).unwrap_or(haystack_len);
    if offset != haystack_len {
        Ok(offset)
    } else {
        Err(Error::new(ErrorKind::Other, format!("Failed to find offset of {} in string!", needle)))
    }
}

fn validate_network_settings(
    network_configuration_type: &NetworkCfgType,
    adapter_name: &str,
    ip_address: &str,
    netmask: &str,
    gateway: &str,
    dns: &str,
) -> Result<NetworkSettings, io::Error> {
    // we now have network_configuration_type:
    // * Eth0 static
    // * Eth0 dhcp
    // * wifi dhcp

    if network_configuration_type == &NetworkCfgType::Ethernet_DHCP {
        // return invalid static info, we are using dhcp
        let mut dhcp_settings = NetworkSettings::new(adapter_name.to_string());
        dhcp_settings.dhcp_enabled = true;
        Ok(dhcp_settings)
    } else if network_configuration_type == &NetworkCfgType::Ethernet_Static {

        let valid_ip_address = match Ipv4Addr::from_str(&ip_address) {
            Ok(eth) => eth,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to parse ip address!")),
        };

        let valid_netmask = match Ipv4Addr::from_str(&netmask) {
            Ok(nm) => nm,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to parse subnet mask!")),
        };

        let valid_gateway = match Ipv4Addr::from_str(&gateway) {
            Ok(gw) => gw,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to parse gateway!")),
        };

        let vec_dns: Vec<&str> = dns.split(',').collect();
        let mut valid_dns_entries = Vec::new();
        for v in vec_dns {
            let trimmed_ip = v.trim();
            match trimmed_ip.parse::<Ipv4Addr>() {
                Ok(entry) => valid_dns_entries.push(entry),
                Err(_) => return Err(Error::new(ErrorKind::Other, "Invalid DNS entry!")),
            };
        }
        valid_dns_entries.dedup();

        // return static setup
        return Ok(NetworkSettings {
            adapter_name: adapter_name.to_string(),
            dhcp_enabled: false,
            ip_address: valid_ip_address,
            netmask: valid_netmask,
            gateway: valid_gateway,
            dns: valid_dns_entries,
        });
    } else if network_configuration_type == &NetworkCfgType::Wifi_DHCP {
        // here we also want invalid ethernet settings but we want
        // store the last connected SSID for future use when switching back and forth for the user.
        let mut wifi_settings = NetworkSettings::new(adapter_name.to_string());
        wifi_settings.dhcp_enabled = true;
        Ok(wifi_settings)
    } else {
        return Err(Error::new(
            ErrorKind::Other,
            "validate_network_settings: Invalid Network configuration type!",
        ));
    }
}

// configure all the network settings in one go.
// wifi and ethernet.
// FIXME: Can this be improved to not create new HBS instances?
fn configure_system_network_settings(
    ethernet_settings: &NetworkSettings,
    wifi_settings: &NetworkSettings,
    static_streaming_ethernet_settings: &NetworkSettings,
    ethernet_output_file: &str,
    wifi_output_file: &str,
    static_streaming_ethernet_output_file: &str)
    -> Result<(), io::Error> {

    if ethernet_settings.dhcp_enabled { //ethernet dhcp, wifi off
        write_network_settings(ethernet_settings, ETHERNET_DHCP_ENABLE_TEMPLATE, ethernet_output_file)?;
        write_network_settings(wifi_settings, WIFI_DISABLE_TEMPLATE, wifi_output_file)?;
    } else if wifi_settings.dhcp_enabled { //wifi dhcp, ethernet on but not routed
        write_network_settings(wifi_settings, WIFI_DHCP_ENABLE_TEMPLATE, wifi_output_file)?;
        write_network_settings(ethernet_settings, ETHERNET_DISABLE_TEMPLATE, ethernet_output_file)?;
    } else {
        write_network_settings(ethernet_settings, ETHERNET_STATIC_SETTINGS_TEMPLATE, ethernet_output_file)?;
        write_network_settings(wifi_settings, WIFI_DISABLE_TEMPLATE, wifi_output_file)?;
    }

    //always write the static network settings out. (eth1 or similar)
    write_network_settings(static_streaming_ethernet_settings, ETHERNET_STATIC_SETTINGS_TEMPLATE, 
                                 static_streaming_ethernet_output_file)?;

    return Ok(());
}

fn write_network_settings(settings: &NetworkSettings, template_path: &str, output_file: &str)
    -> Result<(), io::Error>
{
    let template_input = load_file_as_string(template_path)?;

    let mut h = Handlebars::new();
    assert!(h.register_template_string("static", template_input).is_ok());
    let t = h.render("static", &settings).unwrap();

    write_file_contents(&t.to_string(), output_file, true)?;

    Ok(())
}

pub fn get_network_cfg_type(value: u8) -> Option<NetworkCfgType> {
    let network_configuration_type = match NetworkCfgType::from_u8(value) {
        Some(val) => val,
        None => {
            debug!("invalid form value for network cfg type!");
            return None;
        },
    };

    Some(network_configuration_type)
}
