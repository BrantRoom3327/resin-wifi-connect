#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::process::Command;
use std::net::Ipv4Addr;
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
use server::{collect_do_auth_options, collect_set_config_options, 
    get_kcf_runtime_data, inject_ethernet_static_settings, inject_wifi_settings, exit_http_server, set_shutdown};
use num::FromPrimitive;
use serde_json::Value;
use std::path::Path;

pub const NO_HOTSPOT_SERVER_PORT: i32 = 8080;

//http templates for webpages
pub const HTTP_CONFIG_TEMPLATE: &str = "config";
pub const HTTP_STATUS_TEMPLATE: &str = "status";

// parsing of sd collector xml tags.
pub const PROMETHEUS_TAG_START: &str = "<PrometheusUrl>";
pub const PROMETHEUS_TAG_END: &str = "</PrometheusUrl>";
pub const PROXYSETTINGS_TAG_START: &str = "<ProxySettings>";
pub const PROXYSETTINGS_TAG_END: &str = "</ProxySettings>";

// routes
pub const ROUTE_GET_CONFIG: &str = "/getconfig";
pub const ROUTE_SET_CONFIG: &str = "/setconfig";
pub const ROUTE_AUTH: &str = "/auth";
pub const ROUTE_SHOW_STATUS: &str = "/status";
pub const ROUTE_RESTART: &str = "/restart";

// cookie for auth
pub const COOKIE_NAME: &str = "tastybiscuits";
pub const COOKIE_VALUE: &str = "lemonShortbread";

enum_from_primitive! {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub enum NetworkCfgType {
        Ethernet_Static = 0,
        Ethernet_DHCP = 1,
        Wifi_Static = 2,
        Wifi_DHCP = 3,
        Invalid = 4,
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
            dns: vec!["8.8.8.8".parse().unwrap()],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WifiSettings {
    pub ssid: String,
    pub psk: String,
    pub settings: NetworkSettings,
}

impl WifiSettings {
    pub fn new(adapter_name: String) -> WifiSettings {
        WifiSettings {
            ssid: String::new(),
            psk: String::new(),
            settings: NetworkSettings::new(adapter_name),
        }
    }
    pub fn init(adapter_name: String, ssid: String, psk: String) -> WifiSettings {
        WifiSettings {
            ssid,
            psk,
            settings: NetworkSettings::new(adapter_name),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterfaces {
    pub collector_ethernet: String, //ethernet for upstream to cloud.
    pub collector_wifi: String,     //wifi for upstream to cloud
    pub static_streaming_ethernet: String, //unchanging static addressed interface for streaming
    pub hotspot: String,  //interface the hotspot runs on
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalScripts {
    pub get_ip: String, //script to get the ipaddress of an adapter and return it
    pub get_dns: String, //script to get the dns settings of an adapter and return it
    pub get_gateway: String, //script to get the gateway settings of an adapter and return it
    pub get_netmask: String, //script to get the netmask settings of an adapter and return it
    pub reboot: String, //script that will reboot the device when run.  Used for resin device reboot right now
    pub networking_stub: String, // base script that we inject other script calls into for resin.  Just some simple /bin/bash and an export right now.
    pub configure_connection: String, // script we send commands to configure each connection
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputFiles {
    pub configure_networking: String, //the configuration file we write to setup networking.  Data is injected into this file.
    pub collector_xml_file: String, //conf file read by collector, modified in place by us
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxySettings {
    pub Enabled: bool,
    pub Server: Option<String>,  //option because null
    pub Port: u16,
    pub UseDefaultCredentials: bool,
    pub User: Option<String>,    //option because null
    pub Password: Option<String>, //option because null
}

impl ProxySettings {
    pub fn new() -> ProxySettings {
        ProxySettings {
            Enabled: false,
            Server: None,
            Port: 0,
            UseDefaultCredentials: false,
            User: None,
            Password: None,
        }
    }
    pub fn init(enabled: bool, username: String, password: String, server: String, port: u16) -> ProxySettings {
        ProxySettings {
            Enabled: enabled,
            Server: Some(server),
            Port: port,
            UseDefaultCredentials: false,
            User: Some(username),
            Password: Some(password),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SmartDiagnosticsConfig {
    // cloud storage settings
    pub cloud_storage_enabled: bool,
    pub data_destination_url: String,
    pub network_configuration_type: u8, //at runtime a NetworkCfgType
    pub cookie_key: String,             // master key used to generate cookie hashes.
    pub network_interfaces: NetworkInterfaces,
    pub output_files: OutputFiles,
    pub scripts: ExternalScripts,
    pub templates_dir: String,
    pub exec_script_on_reboot: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetConfigOptionsFromPost {
    pub cloud_storage_enabled: bool,
    pub destination_address: String,
    pub network_configuration_type: u8,
    pub wifi_ssid: String,
    pub wifi_passphrase: String,
    pub ip_address: String,
    pub subnet_mask: String,
    pub gateway: String,
    pub dns: String,
    pub proxy: ProxySettings,
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
    pub proxy_settings: ProxySettings,
    pub ethernet_static_network_settings: NetworkSettings, //used to store ethernet static settings as needed for templating
    pub wifi_network_settings: WifiSettings,  //used to also store static settings as needed for templating
    pub shutting_down: bool,  //the system is shutting down and won't take more commands
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
pub fn validate_cookie_data<'a, 'b>(cookie_key: &'a [u8], cookie: &'b Cookie) -> Result<(), Error> {
    if cookie_key.len() != 64 {
        panic!("validate_cookie_data: The cookie master key is invalid at runtime!\n\n");
    }

    let (name, value) = cookie.name_value();

    if COOKIE_NAME == name && COOKIE_VALUE == value {
        return Ok(());
    } else {
        return Err(Error::new(InvalidData, format!("Cookie is not valid!")));
    };
}

pub fn get_prometheus_url(filename: &str) -> Result<String, Error> {

    let mut xml_data = load_file_as_string(&filename)?;
    
    // find <PrometheusURL>
    let mut prometheus_start = find_offset_in_string(&xml_data, PROMETHEUS_TAG_START)?;
    prometheus_start += PROMETHEUS_TAG_START.len(); //skip to end of string
    let prometheus_end = find_offset_in_string(&xml_data, PROMETHEUS_TAG_END)?;

    //gather data inbetween tags
    let prometheus_url: String = xml_data.drain(prometheus_start..prometheus_end).collect();

    Ok(prometheus_url)
}

pub fn get_proxy_settings(filename: &str) -> Result<ProxySettings, Error> {

    let mut xml_data = load_file_as_string(&filename)?;
    
    // find <ProxySettings>
    let mut proxy_settings_start = find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_START)?;
    proxy_settings_start += PROXYSETTINGS_TAG_START.len();
    let proxy_settings_end = find_offset_in_string(&xml_data, PROXYSETTINGS_TAG_END)?;

    //delete data between tags
    let settings: String = xml_data
        .drain(proxy_settings_start..proxy_settings_end)
        .collect();

    // convert the strange JSON format inside of xml to a ProxySettings type
    let proxy_settings: ProxySettings = serde_json::from_str(&settings)?;

    Ok(proxy_settings)
}

// instead of wiping the line, wipe the data between begin and end tags and insert new.
pub fn update_sd_collector_xml(cfg: &SmartDiagnosticsConfig, proxy_settings: &ProxySettings) -> Result<(), Error>
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

    let collector_string = match serde_json::to_string(&proxy_settings) {
        Ok(json) => json,
        Err(e) => {

            return Err(Error::new(
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

fn validate_http_cookie(req: &mut Request) -> Result<(), Error> {

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
        return Err(Error::new(
                InvalidData, format!("Login invalid or invalid cookie")));
    }

    let c = Cookie::parse(&cookie_str[COOKIE_TAG.len()..]).unwrap();

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");

    match validate_cookie_data(kcf.config_data.cookie_key.as_bytes(), &c) {
        Ok(()) => (),
        Err(err) =>  {
            return Err(Error::new(
                InvalidData, format!("Login invalid or invalid cookie {:?}", err)));
        }
    }

    Ok(())
}

pub fn http_route_restart(req: &mut Request) -> IronResult<Response> {

    println!("Http route restart\n");
    match validate_http_cookie(req) {
        Ok(()) => (),
        Err(e) => {
            return Err(IronError::new(
                Error::new(InvalidData, format!("{:?}", e)),
                status::InternalServerError,
            ))
        }
    }

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    if !kcf.shutting_down {
        set_shutdown(req).expect("Could not set shutdown flag!!\n\n");

        if kcf.config_data.exec_script_on_reboot {
            println!("running network configuration!");
            let output = Command::new(kcf.config_data.output_files.configure_networking)
                .output()
                .expect("failed to execute configure networking script");

            let sout = String::from_utf8(output.stdout).expect("Not UTF-8");
            let serr = String::from_utf8(output.stderr).expect("Not UTF-8");
            println!("stdout: {}", sout);
            println!("stderr: {}", serr);
        } else {
            println!("skipping network configuration\n");
        }

        exit_http_server(req)?;
    } else {
        println!("Already shutting down!");
    }

    Ok(Response::with((status::Found, "Restarting...")))
}

pub fn http_route_set_config(req: &mut Request) -> IronResult<Response> {

    let options = collect_set_config_options(req)?;

    // make sure the network configuration type gets validated here and type converted
    let network_configuration_type = match get_network_cfg_type(options.network_configuration_type) {
        Some(net) => net,
        None => {
            return Err(IronError::new(
                Error::new(InvalidData, format!("Invalid network configuration value")),
                status::InternalServerError,
            ))
        },
    };

    //create a mutable instance of config data, we will edit it and write it back out.
    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    let mut config_data = kcf.config_data.clone();

    // always written out, the streaming collection interface settings that never change.
    let static_streaming_settings = NetworkSettings::get_static_streaming_settings(
            config_data.network_interfaces.static_streaming_ethernet.clone());

    let mut wifi_settings = WifiSettings::init(config_data.network_interfaces.collector_wifi.clone(),
        options.wifi_ssid, options.wifi_passphrase);

    //ethernet is either dhcp or static
    let mut ethernet_settings = NetworkSettings::new(config_data.network_interfaces.collector_ethernet.clone());

    // match here on the networking types and do validation based on that.
    if network_configuration_type == NetworkCfgType::Ethernet_DHCP {
        // configure ethernet for dhcp
        ethernet_settings.dhcp_enabled = true;
    }
    else if network_configuration_type == NetworkCfgType::Ethernet_Static {

        let valid_ip_address = match Ipv4Addr::from_str(&options.ip_address) {
            Ok(eth) => eth,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse IP Address")),
                    status::InternalServerError,
                ))
            }
        };

        let valid_netmask = match Ipv4Addr::from_str(&options.subnet_mask) {
            Ok(nm) => nm,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse subnet mask")),
                    status::InternalServerError,
                ))
            }
        };

        let valid_gateway = match Ipv4Addr::from_str(&options.gateway) {
            Ok(gw) => gw,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse gateway")),
                    status::InternalServerError,
                ))
            }
        };

        let vec_dns: Vec<&str> = options.dns.split(',').collect();
        let mut valid_dns_entries = Vec::new();
        for v in vec_dns {
            let trimmed_ip = v.trim();
            match trimmed_ip.parse::<Ipv4Addr>() {
                Ok(entry) => valid_dns_entries.push(entry),
                Err(_) => {
                    return Err(IronError::new(
                        Error::new(InvalidData, format!("Failed to parse dns entries")),
                        status::InternalServerError,
                    ))
                }
            };
        }
        valid_dns_entries.dedup();

        // map over the dns entries and drop 0.0.0.0 and 127.0.0.1
        valid_dns_entries.retain(|&x| !x.is_unspecified());
        valid_dns_entries.retain(|&x| !x.is_loopback());

        // if we don't have at least one dns entry, fail this call as well, we need to have that set by the user
        if valid_dns_entries.len() == 0 {
            return Err(IronError::new(
                Error::new(InvalidData, format!("No valid DNS entries given!")),
                status::InternalServerError,
            ));
        }

        ethernet_settings = NetworkSettings {
            adapter_name: config_data.network_interfaces.collector_ethernet.to_string(),
            dhcp_enabled: false,
            ip_address: valid_ip_address,
            netmask: valid_netmask,
            gateway: valid_gateway,
            dns: valid_dns_entries,
        };
    }
    else if network_configuration_type == NetworkCfgType::Wifi_Static {

        let valid_ip_address = match Ipv4Addr::from_str(&options.ip_address) {
            Ok(eth) => eth,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse IP Address")),
                    status::InternalServerError,
                ))
            }
        };

        let valid_netmask = match Ipv4Addr::from_str(&options.subnet_mask) {
            Ok(nm) => nm,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse subnet mask")),
                    status::InternalServerError,
                ))
            }
        };

        let valid_gateway = match Ipv4Addr::from_str(&options.gateway) {
            Ok(gw) => gw,
            Err(_) => {
                return Err(IronError::new(
                    Error::new(InvalidData, format!("Failed to parse gateway")),
                    status::InternalServerError,
                ))
            }
        };

        let vec_dns: Vec<&str> = options.dns.split(',').collect();
        let mut valid_dns_entries = Vec::new();
        for v in vec_dns {
            let trimmed_ip = v.trim();
            match trimmed_ip.parse::<Ipv4Addr>() {
                Ok(entry) => valid_dns_entries.push(entry),
                Err(_) => {
                    return Err(IronError::new(
                        Error::new(InvalidData, format!("Failed to parse dns entries")),
                        status::InternalServerError,
                    ))
                }
            };
        }
        valid_dns_entries.dedup();

        // map over the dns entries and drop 0.0.0.0 and 127.0.0.1
        valid_dns_entries.retain(|&x| !x.is_unspecified());
        valid_dns_entries.retain(|&x| !x.is_loopback());

        // if we don't have at least one dns entry, fail this call as well, we need to have that set by the user
        if valid_dns_entries.len() == 0 {
            return Err(IronError::new(
                Error::new(InvalidData, format!("No valid DNS entries given!")),
                status::InternalServerError,
            ));
        }

        wifi_settings.settings = NetworkSettings {
            adapter_name: config_data.network_interfaces.collector_ethernet.to_string(),
            dhcp_enabled: false,
            ip_address: valid_ip_address,
            netmask: valid_netmask,
            gateway: valid_gateway,
            dns: valid_dns_entries,
        };
    }

    // setup ethernet adapter with new settings in config file.
    match configure_system_network_settings(
        &network_configuration_type,
        &ethernet_settings,
        &static_streaming_settings,
        &wifi_settings,
        &config_data)
    {
        Ok(()) => (),
        Err(e) => {
            return Err(IronError::new(
                Error::new(InvalidData, format!("Error configuring network settings! {:?}", e)),
                status::InternalServerError,
            ));
        },
    }

    //
    // update all the configuration data and write it all out
    //

    if !options.cloud_storage_enabled {
        config_data.data_destination_url = options.destination_address;
    }

    // if we get this far, update the configuration, it was successful.
    config_data.cloud_storage_enabled = options.cloud_storage_enabled;
    config_data.network_configuration_type = options.network_configuration_type;

    //
    // inject the new static ethernet or wifi settings into runtime data if chosen.
    //
    match network_configuration_type  {
        NetworkCfgType::Ethernet_Static => inject_ethernet_static_settings(req, ethernet_settings)?,
        NetworkCfgType::Wifi_Static => inject_wifi_settings(req, wifi_settings)?,
        _ => (),
    };

    //
    // Update the sd collector xml file
    //
    if update_sd_collector_xml(&config_data, &options.proxy).is_err() {
        return Err(IronError::new(
            Error::new(InvalidData, format!("Unable to update collector XML file!")),
            status::InternalServerError,
        ));
    }

    //
    // Write out the config_data file for the next server change.
    //

    // NOTE: We never want to touch the data_destination_url in the config file for wifi-connect.  
    // That is written to the collectorsettings.xml but never modified in the wifi-connect config file.  
    // That's why this gets put back.
    config_data.data_destination_url = kcf.config_data.data_destination_url;

    let _status = match write_diagnostics_config(&config_data, &kcf.config_file_path) {
        Ok(s) => s,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError))
        },
    };

    let show_status_route = "http://".to_string() + &kcf.http_server_address + ROUTE_SHOW_STATUS;

    // redirect back to login page on success
    let url = Url::parse(&show_status_route).unwrap();
    Ok(Response::with((status::Found, Redirect(url.clone()))))
}

pub fn http_route_get_config(req: &mut Request) -> IronResult<Response> {

    match validate_http_cookie(req) {
        Ok(()) => (),
        Err(e) => {
            return Err(IronError::new(
                Error::new(InvalidData, format!("{:?}", e)),
                status::InternalServerError,
            ))
        }
    }

    let kcf = get_kcf_runtime_data(req).expect("Couldn't get request state at runtime!");
    let net_settings = match get_network_settings(&kcf.config_data, &kcf.config_data.network_interfaces.collector_ethernet) {
        Some(settings) => settings,
        None => {
            return Ok(Response::with((
                status::Unauthorized,
                "Failed to acquire network settings from ethernet adapter.",
            )))
        },
    };

    //load the collector_settings_xml file and get the current value of the PrometheusURL
    let current_prometheus_url = match get_prometheus_url(&kcf.config_data.output_files.collector_xml_file) {
        Ok(url) => url,
        Err(_e) => {
            return Ok(Response::with((
                status::Unauthorized, "Failed to read the promethus url from file",
            )))
        },
    };

    //load the collector_settings_xml file and get the current value of the ProxySettings 
    let proxy_settings = match get_proxy_settings(&kcf.config_data.output_files.collector_xml_file) {
        Ok(settings) => settings,
        Err(_e) => {
            return Ok(Response::with((
                status::Unauthorized, "Failed to read proxy settings from file",
            )))
        },
    };

    //inject the live network settings into the configuration we have stored and use
    //the merged output for the template render.
    let mut cfg_json = json!(kcf.config_data);
    merge(&mut cfg_json, json!(net_settings));

    //overwritting the value in the config here (key reuse)
    merge(&mut cfg_json, json!({"data_destination_url": current_prometheus_url}));

    //inject the proxy settings to the template data
    merge(&mut cfg_json, json!({"proxy": proxy_settings}));

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
        Err(e) =>  {
            panic!("Failed to read configuration file -> {}! e={:?}\n", kcf.config_file_path, e)
        },
    };

    // merge in the network settings that were sent to the server but are not stored
    // in the cfg file.
    let mut template_json = json!(data_from_cfg_file);

    //only merge in the template data we need based on configuration type.
    let net_cfg = get_network_cfg_type(kcf.config_data.network_configuration_type);
    match net_cfg {
        Some(NetworkCfgType::Ethernet_Static) => {
            merge(&mut template_json, json!(kcf.ethernet_static_network_settings))
        },
        Some(NetworkCfgType::Wifi_DHCP) => {
            merge(&mut template_json, json!(kcf.wifi_network_settings))
        },
        Some(NetworkCfgType::Wifi_Static) => {
            merge(&mut template_json, json!(kcf.wifi_network_settings))
        }
        _ => ()
    }


    let mut resp = Response::new();
    resp.set_mut(Template::new(HTTP_STATUS_TEMPLATE, template_json))
        .set_mut(status::Ok);
    Ok(resp)
}

pub fn get_network_settings(config_data: &SmartDiagnosticsConfig, adapter_name: &str) -> Option<NetworkSettings> {
    let ip_address = get_ip_for_adapter(config_data, adapter_name)?;
    let netmask = get_netmask_for_adapter(config_data, adapter_name)?;
    let gateway = get_gateway_for_adapter(config_data, adapter_name)?;
    let dns = get_dns_entries(config_data, adapter_name)?;

    Some(NetworkSettings {
        adapter_name: adapter_name.to_string(),
        dhcp_enabled: false,
        ip_address,
        netmask,
        gateway,
        dns,
    })
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

pub fn load_file_as_string(file_path: &str) -> Result<String, Error> {
    let mut data = String::new();
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, format!("failed to open file {} err={:?}!", file_path, e)))
        }
    };

    f.read_to_string(&mut data)?;
    Ok(data)
}

pub fn write_file_contents(data: &str, file_path: &str, create_new_file: bool) -> Result<(), Error> {
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
        return Err(Error::new(InvalidData, err_str));
    }
    Ok(())
}

pub fn write_diagnostics_config(config: &SmartDiagnosticsConfig, file_path: &str) -> Result<(), Error>
{
    let data = serde_json::to_string_pretty(&config)?;

    let mut f = OpenOptions::new().write(true).truncate(true).open(file_path)?;
    f.write(data.as_bytes())?;

    Ok(())
}

pub fn find_offset_in_string(haystack: &str, needle: &str) -> Result<usize, Error> {
    let haystack_len = haystack.len();
    let offset = haystack.find(needle).unwrap_or(haystack_len);
    if offset != haystack_len {
        Ok(offset)
    } else {
        Err(Error::new(ErrorKind::Other, format!("Failed to find offset of {} in string!", needle)))
    }
}

// configure all the network settings in one go.
fn configure_system_network_settings(
    network_configuration_type: &NetworkCfgType,
    ethernet_settings: &NetworkSettings,
    static_streaming_ethernet_settings: &NetworkSettings,
    wifi_settings: &WifiSettings,
    config_data: &SmartDiagnosticsConfig) -> Result<(), Error> {

    let mut commands = vec![];
    
    // load the stub into the string vec
    let stub = load_file_as_string(&config_data.scripts.networking_stub)?;
    commands.push(stub);

    if network_configuration_type == &NetworkCfgType::Ethernet_DHCP {
        let eth = write_ethernet_settings(ethernet_settings, false, Some(1))?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, eth));
        let wifi = write_wifi_settings(wifi_settings, true, None)?; //disable wifi with true here
        commands.push(format!("{} {}", config_data.scripts.configure_connection, wifi));
    } else if network_configuration_type == &NetworkCfgType::Ethernet_Static {
        let eth = write_ethernet_settings(ethernet_settings, false, Some(1))?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, eth));
        let wifi = write_wifi_settings(wifi_settings, true, None)?; //disable wifi with true here
        commands.push(format!("{} {}", config_data.scripts.configure_connection, wifi));
    } else if network_configuration_type == &NetworkCfgType::Wifi_DHCP {
        //in the wifi primary case (this case) we still want a ethernet config
        //because network manager will auto create configurations for device that are plugged in.
        //but in this case we are trying to make wifi primary so we want a connection profile but
        //want it NOT to get an address or be routed.  Send true for disable_autoconnect
        let eth = write_ethernet_settings(ethernet_settings, true, None)?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, eth));
        let wifi = write_wifi_settings(wifi_settings, false, Some(1))?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, wifi));
     } else if network_configuration_type == &NetworkCfgType::Wifi_Static {
        let eth = write_ethernet_settings(ethernet_settings, true, None)?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, eth));
        let wifi = write_wifi_settings(wifi_settings, false, Some(1))?;
        commands.push(format!("{} {}", config_data.scripts.configure_connection, wifi));
    } else {
        return Err(Error::new(ErrorKind::Other, "invalid network configuration"));
    }

    // write the streaming data collector settings always
    let eth = write_ethernet_settings(static_streaming_ethernet_settings, false, None)?;
    commands.push(format!("{} {}", config_data.scripts.configure_connection, eth));

    // inject a call to the reboot script here
    // after network settings are applied we will reboot.
    let reboot_string = format!("{}", config_data.scripts.reboot);
    commands.push(reboot_string);
        
    //
    // cat all the strings together into a single string and write it out
    //
    let mut script_out = commands.join("\n");
    script_out.push_str("\n");

    // write out the file.
    match write_file_contents(&script_out, &config_data.output_files.configure_networking, true) {
        Ok(()) => (),
        Err(e) => {
            let reterr = format!("Unable to write wifi settings to file {}, err={:?}", config_data.output_files.configure_networking, e);
            return Err(Error::new(ErrorKind::NotFound, reterr));
        }
    }

    Ok(())
}

/// Write out configuration strings for external script to configure interfaces
fn write_ethernet_settings(settings: &NetworkSettings, disable_autoconnect: bool, metric: Option<i16>) 
    -> Result<String, Error>
{
    // if we plan on disabling this interface just send disable and the name and leave
    if disable_autoconnect {
        return Ok(format!("--interface_name={} --disable=1", settings.adapter_name));
    }

    // we get here if we are not disabling the interface and have real settings.
    let mut config: String;
    if settings.dhcp_enabled {
        config = format!("--interface_name={} --interface_type=ethernet --method=dhcp ", settings.adapter_name);
    } else {
        config = format!("--interface_type=ethernet --method=static --interface_name={} --ip_address={} --gateway={} ", 
                         settings.adapter_name, settings.ip_address, settings.gateway);

        let mut entries = String::new();
        for i in &settings.dns {
            entries.push_str(&format!("{} ", i))
        }
        config = format!("{} --dns_entries='{}' ", config, entries);
    }

    // add metric
    if let Some(ref m) = metric {
        config.push_str(&format!("--metric={}", m));
    }

    //end of the line
    config.push_str(&format!("\n"));

    Ok(config)
}

fn write_wifi_settings(wifi: &WifiSettings, disable_autoconnect: bool, metric: Option<i16>) 
    -> Result<String, Error>
{
    if disable_autoconnect {
       return Ok(format!("--interface_name={} --disable=1", wifi.settings.adapter_name))
    }

    let dhcp_or_static: String;
    if wifi.settings.dhcp_enabled {
        dhcp_or_static = "dhcp".to_string();
    } else {
        dhcp_or_static = "static".to_string();
    }

    let mut returnString = format!("--interface_type=wifi --method={} --interface_name={} --ssid={} --psk={} ", 
                                   dhcp_or_static, wifi.settings.adapter_name, wifi.ssid, wifi.psk);

    //if we are doing static add all the network config
    if !wifi.settings.dhcp_enabled {
        returnString.push_str(&format!(" --ip_address={} --gateway={} ", wifi.settings.ip_address, wifi.settings.gateway));

        let mut entries = String::new();
        for i in &wifi.settings.dns {
            entries.push_str(&format!("{} ", i))
        }
        returnString = format!("{} --dns_entries='{}' ", returnString, entries);
    }

    if let Some(ref m) = metric {
        returnString.push_str(&format!(" --metric={}", m));
    }

    Ok(returnString)
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

/// look for all external files we need on startup and fail if you don't find them
pub fn all_file_deps_exist(config_data: &SmartDiagnosticsConfig) -> Result<(), Error> {

    assert_eq!(true, file_exists(&config_data.scripts.get_ip, "get_ip").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.get_dns, "get_dns").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.get_gateway, "get_gateway").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.get_netmask, "get_netmask").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.reboot, "reboot").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.networking_stub, "networking_stub").is_ok());
    assert_eq!(true, file_exists(&config_data.scripts.configure_connection, "configure_connection").is_ok());
    assert_eq!(true, file_exists(&config_data.output_files.collector_xml_file, "collector_xml_file").is_ok());
    Ok(())
}

pub fn file_exists(filename: &str, fieldname: &str) -> Result<(), Error> {

    if !Path::new(&filename).is_file() {
        println!("File missing {} configuration field name: {}!", filename, fieldname);
        Err(Error::new(ErrorKind::Other, format!("file missing: {}", filename)))
    } else {
        Ok(())
    }
}

// get ip and netmask for the adapter
pub fn get_ip_for_adapter(config_data: &SmartDiagnosticsConfig, adapter_name: &str) -> Option<Ipv4Addr> {
    let output = Command::new(&config_data.scripts.get_ip)
        .arg(adapter_name)
        .output()
        .expect(&format!("failed to execute `{}`", config_data.scripts.get_ip));

    let mut stdout = String::from_utf8(output.stdout).unwrap();
    stdout = stdout.trim().to_string();

    info!("ip: {}", stdout);

    match Ipv4Addr::from_str(&stdout) {
        Ok(eth) => return Some(eth),
        Err(e) => {
            error!("get_ip_for_adapter: Error {:?} adapter {}", e, adapter_name);
            return Some(Ipv4Addr::from_str("0.0.0.0").unwrap());
        }
    }
}

pub fn get_netmask_for_adapter(config_data: &SmartDiagnosticsConfig, adapter_name: &str) -> Option<Ipv4Addr> {
    let output = Command::new(&config_data.scripts.get_netmask)
        .arg(adapter_name)
        .output()
        .expect(&format!("failed to execute `{}`", config_data.scripts.get_netmask));

    let mut stdout = String::from_utf8(output.stdout).unwrap();
    stdout = stdout.trim().to_string();

    match Ipv4Addr::from_str(&stdout) {
        Ok(eth) => return Some(eth),
        Err(e) => {
            error!("get_netmask_for_adapter: Error {:?} adapter {}", e, adapter_name);
            return Some(Ipv4Addr::from_str("0.0.0.0").unwrap());
        }
    }
}

pub fn get_gateway_for_adapter(config_data: &SmartDiagnosticsConfig, adapter_name: &str) -> Option<Ipv4Addr> {
    let output = Command::new(&config_data.scripts.get_gateway)
        .arg(adapter_name)
        .output()
        .expect(&format!("failed to execute `{}`", config_data.scripts.get_gateway));

    let mut stdout = String::from_utf8(output.stdout).unwrap();
    stdout = stdout.trim().to_string();
    info!("gateway: {}", stdout);

    match Ipv4Addr::from_str(&stdout) {
        Ok(eth) => return Some(eth),
        Err(e) => {
            error!("get_gateway_for_adapter: Error {:?} adapter {}", e, adapter_name);
            return Some(Ipv4Addr::from_str("0.0.0.0").unwrap());
        }
    }
}

pub fn get_dns_entries(config_data: &SmartDiagnosticsConfig, adapter_name: &str) -> Option<Vec<Ipv4Addr>> {
    let output = Command::new(&config_data.scripts.get_dns)
        .arg(adapter_name)
        .output()
        .expect(&format!("failed to execute `{}`", config_data.scripts.get_dns));

    let mut stdout = String::from_utf8(output.stdout).unwrap();
    stdout = stdout.trim().to_string();
    info!("script gave dns: {} adapter name is {} script is {}", stdout, adapter_name, config_data.scripts.get_dns);

    let mut vec = Vec::new();

    //NOTE: Expecting string of dns entries, separated by spaces.
    let str_vec: Vec<&str> = stdout.split(" ").collect();
    if str_vec.len() == 0 { //no dns case
        println!("Failed to get any dns!\n");
        vec.push(Ipv4Addr::from_str("0.0.0.0").unwrap());   
    } else if str_vec.len() == 1 && str_vec[0].trim() == "" {
        println!("We got an empty string for dns!\n");
    }
    else {
        for s in str_vec {
            let valid_dns = match Ipv4Addr::from_str(&s) {
                Ok(eth) => eth,
                Err(e) => {
                    error!("get_dns_entries: Error {:?} stdout {}", e, stdout);
                    let no_dns = Ipv4Addr::from_str("0.0.0.0").unwrap();
                    vec.push(no_dns);
                    return Some(vec)
                }
            };
            vec.push(valid_dns);
        }
    }

    Some(vec)
}
