use std::sync::mpsc::{Receiver, Sender};
use std::fmt;
use std::net::Ipv4Addr;
use std::error::Error as StdError;

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

use errors::*;
use network::{NetworkCommand, NetworkCommandResponse};
use exit::{exit, ExitResult};

//kcf imports
use rand::*;
use std::str;
use kcf::*;
use hbs::{DirectorySource, HandlebarsEngine};

#[derive(Debug)]
pub struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
    //kcf specific
    kcf: RuntimeData,
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

impl StdError for StringError {
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

fn exit_with_error<E>(state: &RequestSharedState, e: E, e_kind: ErrorKind) -> IronResult<Response>
where
    E: ::std::error::Error + Send + 'static,
{
    let description = e_kind.description().into();
    let err = Err::<Response, E>(e).chain_err(|| e_kind);
    exit(&state.exit_tx, err.unwrap_err());
    Err(IronError::new(
        StringError(description),
        status::InternalServerError,
    ))
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
    config_file_path: String,
    auth_file_path: String,
) {
    let exit_tx_clone = exit_tx.clone();

    //TODO: Create a function, validate_cookie_key()

    //
    // deserialize SmartDiagnosticsConfig and Auth directly into RunTimeData.
    // use this at runtime to inject configuration state into templates and processing.
    //
    let mut config_data = match load_diagnostics_config_file(&config_file_path) {
        Ok(config) => config,
        Err(e) => panic!(
            "Failed to read configuration file -> {}! e={:?}\n",
            config_file_path, e
        ),
    };

    let auth_data = match load_auth_file(&auth_file_path) {
        Ok(c) => c,
        Err(e) => panic!("Failed to read auth file -> {} !\n", e),
    };

    match all_file_deps_exist(&config_data) {
        Ok(()) => (),
        Err(e) => panic!("Failed to find all templates! {:?}\n", e),
    };
    let templates_dir_clone = config_data.templates_dir.clone();

    // make sure we have a valid cookie seed value.  Needs to be 256 bits.
    // Since its stored as a string we convert 2 chars per string to our 32 bytes of data.
    if config_data.cookie_key.len() != 64 {
        // 32 bytes of data.  2 chars per byte in hex.
        println!("Generating a new cookie creator master key..");
        let mut rng = thread_rng();
        let mut array = vec![0; 8];
        for i in 0..8 {
            array[i] = rng.gen::<u32>();
        }
        let new_key = format!(
            "{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            array[0], array[1], array[2], array[3], array[4], array[5], array[6], array[7]
        );

        println!("New Key -> {} len {}", new_key, new_key.len());
        config_data.cookie_key = new_key;
    }

    let mut http_server_address = gateway.to_string() + ":";
    if cfg!(feature = "no_hotspot") {
        http_server_address += &NO_HOTSPOT_SERVER_PORT.to_string()
    } else {
        http_server_address += "80";
    }

    let http_server_address_clone = http_server_address.clone();
    let kcf = RuntimeData {
        http_server_address,
        config_file_path,
        config_data,
        auth_file_path,
        auth_data,
        ethernet_static_network_settings: NetworkSettings::new("invalid".to_string()),
        wifi_network_settings: WifiSettings::new("invalid".to_string()),
        shutting_down: false,
        proxy_settings: ProxySettings::new(),
    };

    let request_state = RequestSharedState {
        gateway,
        server_rx,
        network_tx,
        exit_tx: exit_tx,
        kcf,
    };

    let mut router = Router::new();
    router.get("/", Static::new(ui_directory), "index");
    router.get("/ssid", ssid, "ssid");
    router.post("/connect", connect, "connect");

    // kcf routes
    router.get(ROUTE_GET_CONFIG, http_route_get_config, "getconfig");
    router.get(ROUTE_SHOW_STATUS, http_route_get_status, "showstatus");
    router.post(ROUTE_AUTH, http_route_do_auth, "auth");
    router.post(ROUTE_SET_CONFIG, http_route_set_config, "setconfig");
    router.post(ROUTE_RESTART, http_route_restart, "restart");
    // end kcf routes

    let mut assets = Mount::new();
    assets.mount("/", router);
    assets.mount("/css", Static::new(&ui_directory.join("css")));
    assets.mount("/img", Static::new(&ui_directory.join("img")));
    assets.mount("/js", Static::new(&ui_directory.join("js")));

    // handlebar style templates
    let mut hbse = HandlebarsEngine::new();

    // load templates
    hbse.add(Box::new(DirectorySource::new(PathBuf::from(templates_dir_clone), PathBuf::from(".hbs"))));

    if let Err(r) = hbse.reload() {
        panic!("{}", r);
    }

    info!(
        "Starting HTTP server on http://{}",
        http_server_address_clone
    );

    let mut chain = Chain::new(assets);
    chain.link(Write::<RequestSharedState>::both(request_state));
    chain.link_after(RedirectMiddleware);
    chain.link_after(hbse);

    if let Err(e) = Iron::new(chain).http(&http_server_address_clone) {
        exit(
            &exit_tx_clone,
            ErrorKind::StartHTTPServer(http_server_address_clone, e.description().into()).into(),
        );
    }
}

fn ssid(req: &mut Request) -> IronResult<Response> {
    info!("User connected to the captive portal");

    let request_state = get_request_state!(req);

    if let Err(e) = request_state.network_tx.send(NetworkCommand::Activate) {
        return exit_with_error(&request_state, e, ErrorKind::SendNetworkCommandActivate);
    }

    let access_points_ssids = match request_state.server_rx.recv() {
        Ok(result) => match result {
            NetworkCommandResponse::AccessPointsSsids(ssids) => ssids,
        },
        Err(e) => return exit_with_error(&request_state, e, ErrorKind::RecvAccessPointSSIDs),
    };

    let access_points_json = match serde_json::to_string(&access_points_ssids) {
        Ok(json) => json,
        Err(e) => return exit_with_error(&request_state, e, ErrorKind::SerializeAccessPointSSIDs),
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

    if let Err(e) = request_state.network_tx.send(command) {
        exit_with_error(&request_state, e, ErrorKind::SendNetworkCommandConnect)
    } else {
        Ok(Response::with(status::Ok))
    }
}

//
// KCF section
//
pub fn collect_set_config_options(req: &mut Request) -> IronResult<SetConfigOptionsFromPost> {
    let params = get_request_ref!(req, Params, "Getting request params failed");

    //cloud settings
    let cloud_storage_enabled = get_param!(params, "cloud_storage_enabled", bool);
    let destination_address = get_param!(params, "destinationaddress", String);
    let enabled = get_param!(params, "proxy_enabled", bool);
    let login = get_param!(params, "proxy_login", String);
    let password = get_param!(params, "proxy_password", String);
    let gateway = get_param!(params, "proxy_gateway", String);
    let port = get_param!(params, "proxy_gateway_port", u16);
    let proxy = ProxySettings::init(enabled, login, password, gateway, port);

    //see NetworkCfgType for the allowed values.
    let network_configuration_type = get_param!(params, "network_configuration_type", u8);

    // settings
    let wifi_ssid = get_param!(params, "wifi_ssid", String);
    let wifi_passphrase = get_param!(params, "wifi_passphrase", String);
    let wifi_ip_address = get_param!(params, "wifi_ip_address", String);
    let wifi_subnet_mask = get_param!(params, "wifi_subnet_mask", String);
    let wifi_gateway = get_param!(params, "wifi_gateway", String);
    let wifi_dns = get_param!(params, "wifi_dns", String);

    let ethernet_ip_address = get_param!(params, "ethernet_ip_address", String);
    let ethernet_subnet_mask = get_param!(params, "ethernet_subnet_mask", String);
    let ethernet_gateway = get_param!(params, "ethernet_gateway", String);
    let ethernet_dns = get_param!(params, "ethernet_dns", String);

    Ok(SetConfigOptionsFromPost {
        cloud_storage_enabled,
        destination_address,
        network_configuration_type,
        proxy,
        wifi_ssid,
        wifi_passphrase,
        wifi_ip_address,
        wifi_subnet_mask,
        wifi_gateway,
        wifi_dns,
        ethernet_ip_address,
        ethernet_subnet_mask,
        ethernet_gateway,
        ethernet_dns,
    })
}

pub fn collect_do_auth_options(req: &mut Request) -> IronResult<Auth> {
    let params = get_request_ref!(req, Params, "Getting request params failed");
    let username = get_param!(params, "username", String);
    let password = get_param!(params, "password", String);

    Ok(Auth { username, password })
}

pub fn get_kcf_runtime_data(req: &mut Request) -> IronResult<RuntimeData> {
    let state = get_request_state!(req);
    Ok(state.kcf.clone())
}

pub fn exit_http_server(req: &mut Request) -> IronResult<()> {
    let request_state = get_request_state!(req);
    println!("Shutdown the webserver at user's request!");

    if let Err(e) = request_state.network_tx.send(NetworkCommand::Exit) {
        exit_with_error(&request_state, e, ErrorKind::SendNetworkCommandActivate)?;
    }

    Ok(())
}

// inject ethernet settings into runtime data.
pub fn inject_ethernet_static_settings(req: &mut Request, settings: NetworkSettings, network_configuration_type: u8) -> IronResult<()> {
    let wr = match req.get::<Write<RequestSharedState>>() {
        Ok(wr) => wr,
        Err(_e) => return Err(IronError::new(StringError("Could not get request shared state".to_string()), status::InternalServerError)),
    };

    wr.as_ref().lock().unwrap().kcf.ethernet_static_network_settings = settings;
    wr.as_ref().lock().unwrap().kcf.config_data.network_configuration_type = network_configuration_type;

    Ok(())
}

// inject wifi settings into runtime data.
pub fn inject_wifi_settings(req: &mut Request, settings: WifiSettings, network_configuration_type: u8) -> IronResult<()> {
    let wr = match req.get::<Write<RequestSharedState>>() {
        Ok(wr) => wr,
        Err(_e) => return Err(IronError::new(StringError("Could not get request shared state".to_string()), status::InternalServerError)),
    };

    wr.as_ref().lock().unwrap().kcf.wifi_network_settings = settings;
    wr.as_ref().lock().unwrap().kcf.config_data.network_configuration_type = network_configuration_type;

    Ok(())
}

pub fn set_shutdown(req: &mut Request) -> IronResult<()> {
    let wr = match req.get::<Write<RequestSharedState>>() {
        Ok(wr) => wr,
        Err(_e) => return Err(IronError::new(StringError("Could not get request shared state".to_string()), status::InternalServerError)),
    };

    wr.as_ref().lock().unwrap().kcf.shutting_down = true;

    Ok(())
}
