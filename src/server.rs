use std::sync::mpsc::{Sender, Receiver};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
//use std::process::Command;
use path::PathBuf;
use iron::prelude::*;
use iron::{Iron, Request, Response, IronResult, status, typemap, IronError, Url, AfterMiddleware, headers};
use iron::modifiers::Redirect;
use router::Router;
use staticfile::Static;
use mount::Mount;
use persistent::{Write};
use params::{Params, FromValue};
use cookie::{CookieJar, Cookie, Key, SameSite};
use config::*;
use hbs::{Template, HandlebarsEngine, DirectorySource};
use network::{NetworkCommand, NetworkCommandResponse, set_ip_and_netmask, set_gateway, set_dns, get_network_settings};
use {exit, ExitResult};
use rand::*;
use std::str;

#[derive(Debug)]
struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    sd_collector_interface: String,  //KCF specific
    http_server_address: String, //KCF specific
}

#[derive(Debug)]
pub struct NetworkSettings {
    pub ip_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr, 
    pub dns: Vec<Ipv4Addr>,
}

impl typemap::Key for RequestSharedState {
    type Value = RequestSharedState;
}

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &*self.0
    }
}

impl fmt::Display for SmartDiagnosticsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

macro_rules! get_request_ref {
    ($req:ident, $ty:ty, $err:expr) => (
        match $req.get_ref::<$ty>() {
            Ok(val) => val,
            Err(err) => {
                error!($err);
                return Err(IronError::new(err, status::InternalServerError));
            }
        }
    )
}

macro_rules! get_param {
    ($params:ident, $param:expr, $ty:ty) => (
        match $params.get($param) {
            Some(value) => {
                match <$ty as FromValue>::from_value(value) {
                    Some(converted) => converted,
                    None => {
                        let err = format!("Unexpected type for '{}'", $param);
                        error!("{}", err);
                        return Err(IronError::new(StringError(err), status::InternalServerError));
                    }
                }
            },
            None => {
                let err = format!("'{}' not found in request params: {:?}", $param, $params);
                error!("{}", err);
                return Err(IronError::new(StringError(err), status::InternalServerError));
            }
        }
    )
}

macro_rules! get_request_state {
    ($req:ident) => (
        get_request_ref!(
            $req,
            Write<RequestSharedState>,
            "Getting reference to request shared state failed"
        ).as_ref().lock().unwrap()
    )
}

macro_rules! exit_with_error {
    ($state:ident, $desc:expr) => (
        {
            exit(&$state.exit_tx, $desc.clone());
            return Err(IronError::new(StringError($desc), status::InternalServerError));
        }
    )
}

struct RedirectMiddleware;

impl AfterMiddleware for RedirectMiddleware {
    fn catch(&self, req: &mut Request, err: IronError) -> IronResult<Response> {
        let gateway = {
            let request_state = get_request_state!(req);
            format!("{}", request_state.gateway)
        };

        if let Some(host) = req.headers.get::<headers::Host>() {
            if host.hostname != gateway {
                let url = Url::parse(&format!("http://{}/", gateway)).unwrap();
                return Ok(Response::with((status::Found, Redirect(url))));
            }
        }

        Err(err)
    }
}

pub fn start_server(
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    ui_path: &PathBuf,
    sd_collector_interface: String,
) {
    let exit_tx_clone = exit_tx.clone();

    let mut cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(config) => config,
        Err(config) => {
            println!("Failed to read/parse configuration file -> {} !\n", CFG_FILE);
            panic!("{:?}", config);
        }
    };

    // make sure we have a valid cookie seed value.  Needs to be 256 bits.
    // Since its stored as a string we convert 2 chars per string to our 32 bytes of data.
    if cfg.cookie_key.len() != 64 { // 32 bytes of data.  2 chars per byte in hex.
        println!("Generating a new cookie creator master key..");
        let mut rng = thread_rng();
        let mut array = vec![0; 8];
        for i in 0..8 {
            array[i] = rng.gen::<u32>();
        }
        let new_key = format!("{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            array[0], array[1], array[2], array[3], array[4], array[5], array[6], array[7]);

        println!("New Key -> {} len {}", new_key, new_key.len());
        cfg.cookie_key = new_key;
    }

    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => panic!("{:?}", err)
    };

    let request_state = RequestSharedState {
        gateway: gateway,
        server_rx: server_rx,
        network_tx: network_tx,
        exit_tx: exit_tx,
        sd_collector_interface: sd_collector_interface,
        http_server_address: gateway.to_string() + ":" + &SERVER_PORT.to_string(),
    };

    let mut router = Router::new();
    router.get("/", Static::new(ui_path), "index");
    router.get("/ssid", ssid, "ssid");
    router.post("/connect", connect, "connect");

    // kcf routes
    router.get(ROUTE_GET_CONFIG, get_config, "getconfig");
    router.get(ROUTE_SHOW_STATUS, get_status, "showstatus");

    router.post(ROUTE_AUTH, do_auth, "auth");
    router.post(ROUTE_SET_CONFIG, set_config, "setconfig");
    // end kcf routes

    let mut assets = Mount::new();
    assets.mount("/", router);
    assets.mount("/css", Static::new(&ui_path.join("css")));
    assets.mount("/img", Static::new(&ui_path.join("img")));
    assets.mount("/js", Static::new(&ui_path.join("js")));

    // handlebar style templates
    let mut hbse = HandlebarsEngine::new();
    hbse.add(Box::new(DirectorySource::new(HTTP_PUBLIC, ".hbs")));
    if let Err(r) = hbse.reload() {
        panic!("{}", r);
    }

    let server_address_clone = request_state.http_server_address.clone();
    info!("Starting HTTP server on http://{}", server_address_clone);

    let mut chain = Chain::new(assets);
    chain.link(Write::<RequestSharedState>::both(request_state));
    chain.link_after(RedirectMiddleware);
    chain.link_after(hbse);

    if let Err(e) = Iron::new(chain).http(&server_address_clone) {
        exit(
            &exit_tx_clone,
            format!("Cannot start HTTP server on '{}': {}", &server_address_clone, e.description()),
        );
    }
}

#[cfg(feature = "localbuild")]
fn ssid(req: &mut Request) -> IronResult<Response> {
    println!("NO Hotspot running in localbuild.  So no settings will be shown.");

    let cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(config) => config,
        Err(config) => {
            println!("Failed to read/parse configuration file -> {} !\n", CFG_FILE);
            panic!("{:?}", config);
        }
    };

    let mut resp = Response::new();
    resp.set_mut(Template::new(WIFI_TEMPLATE_NAME, cfg)).set_mut(status::Ok);
    Ok(resp)
}

#[cfg(not(feature = "localbuild"))]
fn ssid(req: &mut Request) -> IronResult<Response> {
    // used to retrieve ssid's from network manager 
    let request_state = get_request_state!(req);

    if let Err(err) = request_state.network_tx.send(NetworkCommand::Activate) {
        exit_with_error!(
            request_state,
            format!("Sending NetworkCommand::Activate failed: {}", err.description())
        );
    }

    let access_points_ssids = match request_state.server_rx.recv() {
        Ok(result) => {
            match result {
                NetworkCommandResponse::AccessPointsSsids(ssids) => ssids,
            }
        },
        Err(err) => {
            exit_with_error!(
                request_state,
                format!("Receiving access points ssids failed: {}", err.description())
            )
        },
    };

    let access_points_json = match serde_json::to_string(&access_points_ssids) {
        Ok(json) => json,
        Err(err) => {
            exit_with_error!(
                request_state,
                format!("Receiving access points ssids failed: {}", err.description())
            )
        },
    };
    Ok(Response::with((status::Ok, access_points_json)))
}

fn connect(req: &mut Request) -> IronResult<Response> {
    let (ssid, passphrase) = {
        let params = get_request_ref!(req, Params, "Getting request params failed");
        let ssid = get_param!(params, "ssid", String);
        let passphrase = get_param!(params, "passphrase", String);
        (ssid, passphrase)
    };

    debug!("Incoming `connect` to access point `{}` request", ssid);

    let request_state = get_request_state!(req);

    let command = NetworkCommand::Connect {
        ssid: ssid,
        passphrase: passphrase,
    };

    if let Err(err) = request_state.network_tx.send(command) {
        exit_with_error!(
            request_state,
            format!("Sending NetworkCommand::Connect failed: {}", err.description())
        );
    }

    Ok(Response::with(status::Ok))
}

// 
// KCF specific
//
fn set_config(req: &mut Request) -> IronResult<Response> {
    let (cloud_storage_enabled, destination_address, 
         proxy_enabled, proxy_login, proxy_password, proxy_gateway, proxy_gateway_port,
         ethernet_dhcp_enabled, ethernet_ip_address, ethernet_gateway, ethernet_subnet_mask, ethernet_dns) = {
        let params = get_request_ref!(req, Params, "Getting request params failed");

        //cloud setings
        let cloud_storage_enabled = get_param!(params, "cloud_storage_enabled", bool);
        let destination_address = get_param!(params, "destinationaddress", String);

        //proxy settings
        let proxy_enabled = get_param!(params, "proxy", bool);
        let proxy_login = get_param!(params, "proxy_login", String);
        let proxy_password = get_param!(params, "proxy_password", String);
        let proxy_gateway = get_param!(params, "proxy_gateway", String);
        let proxy_gateway_port = get_param!(params, "proxy_gateway_port", u16);

        let ethernet_dhcp_enabled = get_param!(params, "ethernet_dhcp_enabled", bool);
        let ethernet_ip_address = get_param!(params, "ethernet_ip_address", String);
        let ethernet_subnet_mask = get_param!(params, "ethernet_subnet_mask", String);
        let ethernet_gateway = get_param!(params, "ethernet_gateway", String);
        let ethernet_dns = get_param!(params, "ethernet_dns", String);

        (cloud_storage_enabled, destination_address, 
            proxy_enabled, proxy_login, proxy_password, proxy_gateway, proxy_gateway_port,
            ethernet_dhcp_enabled, ethernet_ip_address, ethernet_gateway,ethernet_subnet_mask, ethernet_dns)
    };

    println!("cloud storage enabled {}", cloud_storage_enabled);
    println!("destination {}", destination_address);
    println!("proxy_enabled {}", proxy_enabled);
    println!("proxy_login {}", proxy_login);
    println!("proxy_password {}", proxy_password);
    println!("proxy_gateway {}", proxy_gateway);
    println!("proxy_gateway_port {}", proxy_gateway_port);
    println!("ethernet_dhcp_enabled {}", ethernet_dhcp_enabled);
    println!("ethernet_ip_address {}", ethernet_ip_address);
    println!("ethernet_subnet_mask {}", ethernet_subnet_mask);
    println!("ethernet_gateway {}", ethernet_gateway);
    println!("ethernet_dns {:?}", ethernet_dns);

    //
    // FIXME: Take a mutex.
    //
    let mut cfg = match load_diagnostics_config_file(CFG_FILE) {
        Ok(cfg) => cfg,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    cfg.proxy_enabled = proxy_enabled;
    cfg.cloud_storage_enabled = cloud_storage_enabled;
    cfg.ethernet_dhcp_enabled = ethernet_dhcp_enabled;

    if cloud_storage_enabled {
        cfg.data_destination_url = destination_address;
    }

    if proxy_enabled {
        cfg.proxy_login = proxy_login;
        cfg.proxy_password = proxy_password;
        cfg.proxy_gateway = proxy_gateway;
        cfg.proxy_gateway_port = proxy_gateway_port;
    }

    let state = get_request_state!(req);

    if !ethernet_dhcp_enabled {
        // validate the addresses.
        let ipv4_ethernet_address = match Ipv4Addr::from_str(&ethernet_ip_address) {
            Ok(eth) => eth,
            _ => return Ok(Response::with((status::Unauthorized, "Bad ethernet address")))
        };

        let ipv4_subnet_mask = match Ipv4Addr::from_str(&ethernet_subnet_mask) {
            Ok(eth) => eth,
            _ => return Ok(Response::with((status::Unauthorized, "Bad subnet mask")))
        };

        let ipv4_gateway = match Ipv4Addr::from_str(&ethernet_gateway) {
            Ok(eth) => eth,
            _ => return Ok(Response::with((status::Unauthorized, "Bad gateway")))
        };

        let vec_dns: Vec<&str> = ethernet_dns.split(',').collect();
        let mut ethernet_dns_entries = Vec::new();
        for v in vec_dns {
            let trimmed_ip = v.trim();
            match trimmed_ip.parse::<Ipv4Addr>() {
                Ok(entry) => ethernet_dns_entries.push(entry),
                Err(e) => {
                    println!("Invalid dns entry {} {:?}", v, e);
                    return Err(IronError::new(e, status::InternalServerError))
                }
            };
        } 
        ethernet_dns_entries.dedup();

        match set_ip_and_netmask(&ethernet_ip_address, &ethernet_subnet_mask, &state.sd_collector_interface) {
            Ok(()) => (),
            _ => return Ok(Response::with((status::InternalServerError, "Failed to set IP and netmask")))
        };

        match set_gateway(&ethernet_gateway) {
            Ok(()) => (),
            _ => return Ok(Response::with((status::InternalServerError, "Failed to set gateway")))
        };

        match set_dns(&ethernet_dns_entries) {
            Ok(()) => (),
            _ => return Ok(Response::with((status::InternalServerError, "Failed to set dns")))
        };

        // if we get this far, update the configuration, it was successful.
        cfg.ethernet_ip_address = ethernet_ip_address;
        cfg.ethernet_subnet_mask = ethernet_subnet_mask;
        cfg.ethernet_gateway = ethernet_gateway;

        // convert to strings for assignment
        cfg.ethernet_dns = [].to_vec();
        for ns in ethernet_dns_entries {
            cfg.ethernet_dns.push(ns.to_string());
        }
    } else {
        // TODO: enable DHCP on the ethernet interface.
    }
    
    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    let show_status_route = "http://".to_string() + &state.http_server_address + ROUTE_SHOW_STATUS;

    // redirect back to login page on success
    let url = Url::parse(&show_status_route).unwrap();
    Ok(Response::with((status::Found, Redirect(url.clone()))))
}

pub fn get_config(req: &mut Request) -> IronResult<Response> {

    let headers = req.headers.to_string();
    let mut cookie_str = String::new();
    let cookie_prefix_len = "Cookie:".len();

    //TODO: try using a match guard
    for line in headers.lines() {
        let offset = match line.find("Cookie:") {
            Some(index) => index,
            None => headers.len(),
        };
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

    let state = get_request_state!(req);
    let net_settings = match get_network_settings(&state.sd_collector_interface) {
        Some(settings) => settings,
        None => {
            println!("No network settings returned");
                NetworkSettings{ip_address: "0.0.0.0".parse().unwrap(),
                                netmask: "0.0.0.0".parse().unwrap(),
                                gateway: "0.0.0.0".parse().unwrap(),
                                dns: Vec::new(),
                                }
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

    let (user, pass) = {
        let params = get_request_ref!(req, Params, "Getting request params failed");
        let user = get_param!(params, "username", String);
        let pass = get_param!(params, "password", String);
        (user, pass)
    };

    let creds = load_auth_file(AUTH_FILE).expect("Auth failed");

    let auth_ok = if user == creds.username && pass == creds.password 
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

    let state = get_request_state!(req); //for getting http server address
    let get_config_route = "http://".to_string() + &state.http_server_address + ROUTE_GET_CONFIG;

    let url = Url::parse(&get_config_route).unwrap();

    let mut resp = match auth_ok {
        true => Response::with((status::Found, Redirect(url.clone()))),
        false => Response::with((status::Unauthorized, "Bad login"))
    };

    if auth_ok {
        let cookie_str = create_cookie(cfg.cookie_key.as_bytes());
        resp.headers.append_raw("Set-Cookie", cookie_str.into_bytes());
    }

    println!("server response:\n{:?}", resp);
    Ok(resp)
}

pub fn get_status(req: &mut Request) -> IronResult<Response> {

    /// create a live serde cfg object with all the status info
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

// FIXME : lifetime of Result<String, io::Error>
fn create_cookie(cookie_key: &[u8]) -> String {
    if cookie_key.len() != 64 {
        panic!("create_cookie: The cookie master key is invalid at runtime!  This shouldn't happen!\n\n");
    }
    println!("Create a cookie2!\n");
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
fn validate_cookie<'a, 'b>(cookie_key: &'a [u8], cookie: &'b Cookie) -> bool {
    if cookie_key.len() != 64 {
        panic!("validate_cookie: The cookie master key is invalid at runtime!  This shouldn't happen!\n\n");
    }

    let (name, value) = cookie.name_value();
    println!("Validate -> name {} cookie value {}", name, value);

    let auth = if (COOKIE_NAME == name && COOKIE_VALUE == value) {
        true
    } else {
        false
    };

    auth
}
