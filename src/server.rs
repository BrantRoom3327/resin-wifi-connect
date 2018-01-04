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

use config::{AUTH_FILE, SERVER_PORT, CONFIG_PAGE, SmartDiagnosticsConfig,
             get_http_address, load_auth, write_diagnostics_config, read_diagnostics_config};

use std::fs::File;
use std::env;

use hbs::{HandlebarsEngine, DirectorySource};
//use hbs::handlebars::{Handlebars, RenderContext, RenderError, Helper};

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
            println!("Failed to read configuration file for diagnostics on startup!");
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
    router.get("/config", get_configuration, "config");
    router.post("/setdatasource", set_configuration, "set_config");
    // end kcf routes

    let mut assets = Mount::new();
    assets.mount("/", router);
    assets.mount("/css", Static::new(&ui_path.join("css")));
    assets.mount("/img", Static::new(&ui_path.join("img")));
    assets.mount("/js", Static::new(&ui_path.join("js")));

    // handlebar style templates
    let mut hbse = HandlebarsEngine::new();
    hbse.add(Box::new(DirectorySource::new("./public/", ".hbs")));
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

fn set_configuration(req: &mut Request) -> IronResult<Response> {
    let destination_address = {
        let params = get_request_ref!(req, Params, "Getting request params failed");
        let address = get_param!(params, "destinationaddress", String);
        address
    };

    println!("Incoming address -> {} ", destination_address);

    // FIXME: Take a mutex or lock one shared one that exists.
    let mut cfg = match read_diagnostics_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    cfg.data_destination_url = destination_address;
    
    let status = match write_diagnostics_config(&cfg) {
        Ok(s) => s,
        Err(err) => {
            return Err(IronError::new(err, status::InternalServerError));
        }
    };

    //FIXME:
    // if we succeed, redirect back to the login screen...

    Ok(Response::with(status::Ok))
}

// can we close over the ironrequest and make our own method to inject file serving?
pub fn get_configuration(req: &mut Request) -> IronResult<Response> {
    let mut path = env::current_dir().unwrap();
    path.push(CONFIG_PAGE);

    // TODO templating
    //let template_data = get_template_data();
    // TODO: read the cfg file at startup.  Use that config throughout.
    //TODO: Need to read the config file and load the data

    let content_type = "text/html".parse::<Mime>().unwrap();
    let file = File::open(path).unwrap();
    Ok(Response::with((content_type, status::Ok, file)))
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
    address.push_str("/config");

    let url = Url::parse(&address).unwrap();

    let resp = match auth_ok {
        true => Response::with((status::Found, Redirect(url.clone()))),
        false => Response::with((status::Unauthorized, "Bad login"))
    };

    println!("resp is {:?}", resp);
    Ok(resp)
}

pub fn exit_with_error2(exit_tx: &Sender<ExitResult>, error: String) {
    println!("failed a sender command err"); 
}
