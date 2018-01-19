use std::io::{ErrorKind, Error};
use clap::{Arg, App};
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::io::prelude::*;
use std::fs::File;
use std::fs::OpenOptions;
use serde_json;

pub const SERVER_PORT: i32 = 8080;
const DEFAULT_GATEWAY: &str = "192.168.42.1";
const DEFAULT_DHCP_RANGE: &str = "192.168.42.2,192.168.42.254";
const DEFAULT_SSID: &str = "QuarterMaster";
const DEFAULT_TIMEOUT_MS: &str = "15000";
const DEFAULT_UI_PATH: &str = "public";

// this is an alias for public/config.hbs as that is handlebar style naming, but the extensions are stripped for runtime
pub const HTTP_PUBLIC: &str = "./public/";
pub const CONFIG_TEMPLATE_NAME: &str = "config";
pub const STATUS_TEMPLATE_NAME: &str = "status";

//required config and auth files for the server to validate connections and store persistent data.
pub const AUTH_FILE: &str = "auth.json";
pub const CFG_FILE: &str = "cfg.json";
const DEFAULT_SD_COLLECTOR_INTERFACE: &str = "eth0";

// routes
pub const ROUTE_GET_CONFIG: &str = "/getconfig";
pub const ROUTE_SET_CONFIG: &str = "/setconfig";
pub const ROUTE_AUTH: &str = "/auth";
pub const ROUTE_SHOW_STATUS : &str = "/status";

// cookie for auth
pub const COOKIE_NAME: &str = "tastybiscuits";
pub const COOKIE_VALUE: &str = "lemonShortbread";
pub const COOKIE_EXPIRES_HOURS: i32 = 1;

pub struct Config {
    pub interface: Option<String>,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub clear: bool,
    pub gateway: Ipv4Addr,
    pub dhcp_range: String,
    pub timeout: u64,
    pub ui_path: PathBuf,
    pub sd_collector_interface: String,  //kcf, "eth0" or "eth1" etc
}

//KCF specific data storage
#[derive(Serialize, Deserialize, Debug)]
pub struct SmartDiagnosticsConfig {
    // cloud storage settings
    pub cloud_storage_enabled: bool,
    pub data_destination_url: String,

    // sd collector ip address settings.
    pub ethernet_dhcp_enabled: bool,
    pub ethernet_ip_address: String,
    pub ethernet_subnet_mask: String,
    pub ethernet_gateway: String,
    pub ethernet_dns: String,

    // proxy settings
    pub proxy_enabled: bool,
    pub proxy_login: String,
    pub proxy_password: String,
    pub proxy_gateway: String,
    pub proxy_gateway_port: u16,

    // master key used to generate cookie hashes.
    pub cookie_key: String,

    // used as a cache right now, set at runtime on start.
    //TODO: find a better place to store this.
    pub http_server_address: String,
}

#[derive(Serialize)]
pub struct SDCollectorProxySettings {
    pub Enabled: bool,
    pub Server: String,
    pub Port: u16,
    pub UseDefaultCredientials: bool,
    pub User: String,
    pub Password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Auth{
    pub username: String,
    pub password: String,
}

pub fn get_config() -> Config {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("portal-interface")
                .short("i")
                .long("portal-interface")
                .value_name("interface")
                .help("Portal interface")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("portal-ssid")
                .short("s")
                .long("portal-ssid")
                .value_name("ssid")
                .help("Portal SSID")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("portal-passphrase")
                .short("p")
                .long("portal-passphrase")
                .value_name("passphrase")
                .help("Portal passphrase")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("portal-gateway")
                .short("g")
                .long("portal-gateway")
                .value_name("gateway")
                .help("Portal gateway")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("portal-dhcp-range")
                .short("d")
                .long("portal-dhcp-range")
                .value_name("dhcp_range")
                .help("Portal DHCP range")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .value_name("timeout")
                .help("Connect timeout (milliseconds)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("clear")
                .short("c")
                .long("clear")
                .value_name("true|false")
                .help("Clear saved WiFi credentials (default: true)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ui-path")
                .short("u")
                .long("ui-path")
                .value_name("ui_path")
                .help("Web UI location")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sd-collector-interface")
                .short("e")
                .long("sd-collector-interface")
                .value_name("sd_collector_interface")
                .help("Ethernet device (e.g eth0) for collector")
                .takes_value(true),
        )
        .get_matches();

    let interface: Option<String> = matches.value_of("portal-interface").map_or_else(
        || env::var("PORTAL_INTERFACE").ok(),
        |v| Some(v.to_string()),
    );

    let ssid: String = matches.value_of("portal-ssid").map_or_else(
        || env::var("PORTAL_SSID").unwrap_or_else(|_| DEFAULT_SSID.to_string()),
        String::from,
    );

    let passphrase: Option<String> = matches.value_of("portal-passphrase").map_or_else(
        || env::var("PORTAL_PASSPHRASE").ok(),
        |v| Some(v.to_string()),
    );

    let clear = matches.value_of("clear").map_or(true, |v| !(v == "false"));

    let gateway = Ipv4Addr::from_str(&matches.value_of("portal-gateway").map_or_else(
        || env::var("PORTAL_GATEWAY").unwrap_or_else(|_| DEFAULT_GATEWAY.to_string()),
        String::from,
    )).expect("Cannot parse gateway address");

    let dhcp_range = matches.value_of("portal-dhcp-range").map_or_else(
        || env::var("PORTAL_DHCP_RANGE").unwrap_or_else(|_| DEFAULT_DHCP_RANGE.to_string()),
        String::from,
    );

    //kcf specific
    let sd_collector_interface = matches.value_of("sd-collector-interface").map_or_else(
        || env::var("SD_COLLECTOR_INTERFACE").unwrap_or_else(|_| DEFAULT_SD_COLLECTOR_INTERFACE.to_string()),
        String::from,
    );
    println!("The collector interface: {}", &sd_collector_interface);

    // TODO: network_manager receives the timeout in seconds, should be ms instead.
    let timeout = u64::from_str(&matches.value_of("timeout").map_or_else(
        || env::var("CONNECT_TIMEOUT").unwrap_or_else(|_| DEFAULT_TIMEOUT_MS.to_string()),
        String::from,
    )).expect("Cannot parse connect timeout") / 1000;

    let ui_path = get_ui_path(matches.value_of("ui-path"));

    Config {
        interface: interface,
        ssid: ssid,
        passphrase: passphrase,
        clear: clear,
        gateway: gateway,
        dhcp_range: dhcp_range,
        timeout: timeout,
        ui_path: ui_path,
        sd_collector_interface: sd_collector_interface,
    }
}

fn get_ui_path(cmd_ui_path: Option<&str>) -> PathBuf {
    if let Some(ui_path) = cmd_ui_path {
        return PathBuf::from(ui_path);
    }

    if let Ok(ui_path) = env::var("UI_PATH") {
        return PathBuf::from(ui_path);
    }

    if let Some(install_ui_path) = get_install_ui_path() {
        return install_ui_path;
    }

    PathBuf::from(DEFAULT_UI_PATH)
}

/// Checks whether `WiFi Connect` is running from install path and whether the
/// UI directory is present in a corresponding location
/// e.g. /usr/local/sbin/wifi-connect -> /usr/local/share/wifi-connect/ui
fn get_install_ui_path() -> Option<PathBuf> {
    if let Ok(exe_path) = env::current_exe() {
        if let Ok(mut path) = exe_path.canonicalize() {
            path.pop();

            match path.file_name() {
                Some(file_name) => {
                    if file_name != OsStr::new("sbin") {
                        // not executing from `sbin` folder
                        return None;
                    }
                },
                None => return None,
            }

            path.pop();
            path.push("share");
            path.push(env!("CARGO_PKG_NAME"));
            path.push("ui");

            if path.is_dir() {
                return Some(path);
            }
        }
    }

    None
}

//
//
// KCF section
//
//

pub fn load_auth(file_path: &str) -> Result<Auth, Error> {
    let mut data = String::new();
    let mut f = File::open(file_path)?;
    f.read_to_string(&mut data)?;
    let auth: Auth = serde_json::from_str(&data[..])?;
    Ok(auth)
}

pub fn load_resolv_conf(file_path: &str) -> Result<String, Error> {
    let mut data = String::new();
    let mut f = File::open(file_path)?;
    f.read_to_string(&mut data)?;
    Ok(data)
}

pub fn read_diagnostics_config() -> Result<SmartDiagnosticsConfig, Error> {
    let mut data = String::new();
    let mut f = File::open(CFG_FILE)?;
    f.read_to_string(&mut data)?;
    let cfg: SmartDiagnosticsConfig = serde_json::from_str(&data[..])?;
    Ok(cfg)
}

pub fn write_diagnostics_config(config: &SmartDiagnosticsConfig) -> Result<(), Error> {

    let mut f = match OpenOptions::new().write(true).truncate(true).open(CFG_FILE) {
        Ok(f) => f,
        Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to open config file!"))
    };

    let data = match serde_json::to_string(&config) {
        Ok(data) => data,
        Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to create json!"))
    };

    let bytes_out = match f.write(data.as_bytes()) {
        Ok(bytes) => bytes,
        Err(e) => return Err(Error::new(ErrorKind::Other, "failed o write out data!"))
    };

    Ok(())
}

