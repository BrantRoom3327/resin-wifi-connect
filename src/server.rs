use std::sync::mpsc::{Receiver, Sender};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

use serde_json;
use path::PathBuf;
use iron::prelude::*;
use iron::{headers, status, typemap, AfterMiddleware, Iron, IronError, IronResult, Request,
           Response, Url};
use iron::modifiers::Redirect;
use router::Router;
use staticfile::Static;
use mount::Mount;
use persistent::Write;
use params::{FromValue, Params};

use network::{NetworkCommand, NetworkCommandResponse};
use {exit, ExitResult};

//kcf imports
use rand::*;
use std::str;
use kcf::*;
use hbs::{HandlebarsEngine, DirectorySource};
use std::io;

#[derive(Debug)]
pub struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    //kcf specific
    kcf: KCFRuntimeData,
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
    ui_directory: &PathBuf,
    collector_ethernet: String,
    collector_wifi: String,
) {
    let exit_tx_clone = exit_tx.clone();

     //TODO: Create a function, validate_cookie_key()

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

    let kcf = KCFRuntimeData {
        collector_ethernet,
        collector_wifi,
        http_server_address: gateway.to_string() + ":",
    };

    let mut request_state = RequestSharedState {
        gateway,
        server_rx,
        network_tx,
        exit_tx,
        kcf, //kcf specific
    };

    if cfg!(feature = "no_hotspot") {
        request_state.kcf.http_server_address += &NO_HOTSPOT_SERVER_PORT.to_string()
    } else {
        request_state.kcf.http_server_address += "80"
    }

    let mut router = Router::new();
    router.get("/", Static::new(ui_directory), "index");
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
    assets.mount("/css", Static::new(&ui_directory.join("css")));
    assets.mount("/img", Static::new(&ui_directory.join("img")));
    assets.mount("/js", Static::new(&ui_directory.join("js")));

    // handlebar style templates
    let mut hbse = HandlebarsEngine::new();
    hbse.add(Box::new(DirectorySource::new(HTTP_PUBLIC, ".hbs")));
    if let Err(r) = hbse.reload() {
        panic!("{}", r);
    }

    let server_address_clone = request_state.kcf.http_server_address.clone();
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

fn ssid(req: &mut Request) -> IronResult<Response> {
    info!("User connected to the captive portal");

    let request_state = get_request_state!(req);

    if let Err(err) = request_state.network_tx.send(NetworkCommand::Activate) {
        exit_with_error!(
            request_state,
            format!(
                "Sending NetworkCommand::Activate failed: {}",
                err.description()
            )
        );
    }

    let access_points_ssids = match request_state.server_rx.recv() {
        Ok(result) => match result {
            NetworkCommandResponse::AccessPointsSsids(ssids) => ssids,
        },
        Err(err) => exit_with_error!(
            request_state,
            format!(
                "Receiving access points ssids failed: {}",
                err.description()
            )
        ),
    };

    let access_points_json = match serde_json::to_string(&access_points_ssids) {
        Ok(json) => json,
        Err(err) => exit_with_error!(
            request_state,
            format!(
                "Serializing access points ssids failed: {}",
                err.description()
            )
        ),
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
            format!(
                "Sending NetworkCommand::Connect failed: {}",
                err.description()
            )
        );
    }

    Ok(Response::with(status::Ok))
}

//
// KCF section
//
pub fn collect_set_config_options(req: &mut Request) -> IronResult<SetConfigOptionsFromPost> {
    let params = get_request_ref!(req, Params, "Getting request params failed");

    //cloud settings
    let cloud_storage_enabled = get_param!(params, "cloud_storage_enabled", bool);
    let destination_address = get_param!(params, "destinationaddress", String);
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

    Ok(SetConfigOptionsFromPost{ cloud_storage_enabled, destination_address, proxy_enabled, proxy_login,
        proxy_password, proxy_gateway, proxy_gateway_port, ethernet_dhcp_enabled, ethernet_ip_address, 
        ethernet_subnet_mask, ethernet_gateway, ethernet_dns})
}

pub fn collect_do_auth_options(req: &mut Request) -> IronResult<Auth> {
    let params = get_request_ref!(req, Params, "Getting request params failed");
    let username = get_param!(params, "username", String);
    let password = get_param!(params, "password", String);

    Ok(Auth {username, password})
}

pub fn get_kcf_runtime_data(req: &mut Request) -> Result<KCFRuntimeData, IronError> {
    let state = get_request_state!(req);
    Ok(state.kcf.clone())
}