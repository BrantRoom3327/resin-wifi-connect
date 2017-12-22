use std::sync::mpsc::{Sender, Receiver};
use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

use serde_json;
use path::PathBuf;
use iron::prelude::*;
use iron::{Iron, Request, Response, IronResult, status, typemap, IronError, 
            Url, AfterMiddleware, headers};
use iron::modifiers::Redirect;
use iron::mime::Mime;

use router::Router;
use staticfile::Static;
use mount::Mount;
use persistent::Write;
use params::{Params, FromValue};

use config::CFG_FILE;
use config::AUTH_FILE;
use config::load_auth;
use config::Auth;

use std::fs::OpenOptions;
use std::io::Write as WriteFile;
use std::fs::File;
use std::env;

use network::{NetworkCommand, NetworkCommandResponse};
use {exit, ExitResult};


#[derive(Debug)]
struct RequestSharedState {
    gateway: Ipv4Addr,
    server_rx: Receiver<NetworkCommandResponse>,
    network_tx: Sender<NetworkCommand>,
    exit_tx: Sender<ExitResult>,
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
    ui_path: &PathBuf,
) {
    let exit_tx_clone = exit_tx.clone();
    let gateway_clone = gateway;
    let request_state = RequestSharedState {
        gateway: gateway,
        server_rx: server_rx,
        network_tx: network_tx,
        exit_tx: exit_tx,
    };

 //   rocket::ignite().mount("/hello", routes![hello]).launch();

    let mut router = Router::new();
    router.get("/", Static::new(ui_path), "index");
    router.get("/ssid", ssid, "ssid");
    router.get("/config", getconfig, "config");

    router.post("/auth", do_auth, "auth");
    router.post("/connect", connect, "connect");

    let mut assets = Mount::new();
    assets.mount("/", router);
    assets.mount("/css", Static::new(&ui_path.join("css")));
    assets.mount("/img", Static::new(&ui_path.join("img")));
    assets.mount("/js", Static::new(&ui_path.join("js")));

    let mut chain = Chain::new(assets);
    chain.link(Write::<RequestSharedState>::both(request_state));
    chain.link_after(RedirectMiddleware);

    let address = format!("{}:8080", gateway_clone);

    info!("Starting HTTP server on {}", &address);

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

fn setconfig(req: &mut Request) -> IronResult<Response> {
    let cloudurl = {
        let params = get_request_ref!(req, Params, "Getting request params failed");
        let url = get_param!(params, "cloudurl", String);
        (url)
    };

    println!("Incoming you suck cloudurl -> {} ", cloudurl);

    Ok(Response::with(status::Ok))
}

fn getconfig(req: &mut Request) -> IronResult<Response> {
    println!("cur dir {:?}", env::current_exe().unwrap());

    let content_type = "text/html".parse::<Mime>().unwrap();
    let file = File::open("/home/loop/resin-wifi-connect/public/config.html").unwrap();
    Ok(Response::with((content_type, status::Ok, file)))
}

fn do_auth(req: &mut Request) -> IronResult<Response> {
    let (user, pass) = {
        let params = get_request_ref!(req, Params, "Getting request params failed");
        let user = get_param!(params, "username", String);
        let pass = get_param!(params, "password", String);
        (user, pass)
    };

    let creds = load_auth(AUTH_FILE).expect("Auth failed");

    println!("Incoming user {} pass {}", user, pass);

    let mut auth_ok = false;
    if user == creds.username &&
       pass == creds.password {
        println!("Auth ok");
        auth_ok = true;
    }

    let url = Url::parse("http://192.168.1.169:8080/config").unwrap();
    let errorurl = Url::parse("http://www.google.com").unwrap();

    // This works!  use status::Found for return on redirect

    let resp = match auth_ok {
        true => {
            Response::with((status::Found, Redirect(url.clone())))
        },
        false => {
            Response::with((status::Unauthorized, "Bad login"))
        }
    };

    println!("resp is {:?}", resp);
    Ok(resp)
}
