use std::sync::mpsc::{Sender, Receiver};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

use serde_json;
use path::PathBuf;
use iron::prelude::*;
use iron::{Iron, Request, Response, IronResult, status, typemap, IronError, Url, AfterMiddleware, headers};
use iron::modifiers::Redirect;
use iron::mime::Mime;

use router::Router;
use staticfile::Static;
use mount::Mount;
use persistent::Write;
use params::{Params, FromValue};

use config::{AUTH_FILE, SERVER_PORT, HTTP_PUBLIC, CONFIG_TEMPLATE_NAME, ROUTE_GET_CONFIG, ROUTE_SET_CONFIG, CFG_FILE,
             SmartDiagnosticsConfig, get_http_address, load_auth, write_diagnostics_config, read_diagnostics_config};

use std::fs::File;

use hbs::{Template, HandlebarsEngine, DirectorySource, MemorySource};

use network::{NetworkCommand, NetworkCommandResponse};
use {exit, ExitResult};

#[derive(Debug)]
struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>
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
) {
    let exit_tx_clone = exit_tx.clone();
    let gateway_clone = gateway;

    let diagnostics = match read_diagnostics_config() {
        Ok(config) => config,
        Err(config) => {
            println!("Failed to read/parse configuration file -> {} !\n", CFG_FILE);
            panic!("{:?}", config);
        }
    };

    let request_state = RequestSharedState {
        gateway: gateway,
        server_rx: server_rx,
        network_tx: network_tx,
        exit_tx: exit_tx,
    };

    let mut router = Router::new();
    router.get("/", Static::new(ui_path), "index");
    router.get("/ssid", ssid, "ssid");
    router.post("/connect", connect, "connect");

    // kcf routes
    router.post("/auth", do_auth, "auth");
    router.get(ROUTE_GET_CONFIG, get_config, "getconfig");
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

    let mut chain = Chain::new(assets);
    chain.link(Write::<RequestSharedState>::both(request_state));
    chain.link_after(RedirectMiddleware);
    chain.link_after(hbse);

    let address = format!("{}:{}", gateway, SERVER_PORT);

    info!("Starting HTTP server on http://{}", &address);

    if let Err(e) = Iron::new(chain).http(&address) {
        exit(
            &exit_tx_clone,
            format!("Cannot start HTTP server on '{}': {}", &address, e.description()),
        );
    }
}

fn ssid(req: &mut Request) -> IronResult<Response> {
    debug!("Incoming `ssid` request");

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
    println!("connect() called with a request");
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
         proxy_enabled, proxy_login, proxy_password, proxy_gateway, proxy_gateway_port) = {
        let params = get_request_ref!(req, Params, "Getting request params failed");

        //cloud setings
        let cloud_storage_enabled = get_param!(params, "cloud_storage_enabled", bool);
        let destination_address = get_param!(params, "destinationaddress", String);

        //proxy settings
        let proxy_enabled = get_param!(params, "proxy_on", bool);
        let proxy_login = get_param!(params, "proxy_login", String);
        let proxy_password = get_param!(params, "proxy_password", String);
        let proxy_gateway = get_param!(params, "proxy_gateway", String);
        let proxy_gateway_port = get_param!(params, "proxy_gateway_port", u16);

        (cloud_storage_enabled, destination_address, 
            proxy_enabled, proxy_login, proxy_password, proxy_gateway, proxy_gateway_port)
    };

    println!("cloud storage enabled {}", cloud_storage_enabled);
    println!("destination {}", destination_address);
    println!("proxy_enabled {}", proxy_enabled);
    println!("proxy_login {}", proxy_login);
    println!("proxy_password {}", proxy_password);
    println!("proxy_gateway {}", proxy_gateway);
    println!("proxy_gateway_port {}", proxy_gateway_port);

    //
    // FIXME: Take a mutex.
    //
    let mut cfg = match read_diagnostics_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    cfg.proxy_enabled = proxy_enabled;
    cfg.cloud_storage_enabled = cloud_storage_enabled;

    if cloud_storage_enabled {
        cfg.data_destination_url = destination_address;
    }

    if proxy_enabled {
        cfg.proxy_login = proxy_login;
        cfg.proxy_password = proxy_password;
        cfg.proxy_gateway = proxy_gateway;
        cfg.proxy_gateway_port = proxy_gateway_port;
    }
    
    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    //Consider redirecting to a status page showing you current configuration.

    // redirect back to login page on success
    let address = get_http_address();
    let url = Url::parse(&address).unwrap();
    Ok(Response::with((status::Found, Redirect(url.clone()))))
}

// can we close over the ironrequest and make our own method to inject file serving?
pub fn get_config(req: &mut Request) -> IronResult<Response> {
    let cfg = match read_diagnostics_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

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

    let creds = load_auth(AUTH_FILE).expect("Auth failed");

    let mut auth_ok = false;
    if user == creds.username &&
       pass == creds.password {
        auth_ok = true;
    }

    // parse the ip based on the hardcoded gateway ip
    let mut address = get_http_address();
    address.push_str(ROUTE_GET_CONFIG);

    let url = Url::parse(&address).unwrap();

    let resp = match auth_ok {
        true => Response::with((status::Found, Redirect(url.clone()))),
        false => Response::with((status::Unauthorized, "Bad login"))
    };

    //println!("resp is {:?}", resp);
    Ok(resp)
}

pub fn exit_with_error2(exit_tx: &Sender<ExitResult>, error: String) {
    println!("failed a sender command err"); 
}
