#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate clap;
extern crate network_manager;
extern crate iron;
extern crate router;
extern crate staticfile;
extern crate mount;
extern crate serde_json;
extern crate persistent;
extern crate params;
extern crate handlebars;
extern crate handlebars_iron as hbs;

#[macro_use]
extern crate serde_derive;

mod config;
mod network;
mod server;
mod dnsmasq;
mod logger;

use std::error::Error;
use std::path;
use std::thread;
use std::sync::mpsc::{channel, Sender};

use config::get_config;

//FIXME use these or don't based on compile options
use network::{process_network_commands, handle_existing_wifi_connections, start_network_manager_service};
use network::{process_network_commands2};

pub type ExitResult = Result<(), String>;

pub fn exit(exit_tx: &Sender<ExitResult>, error: String) {
    let _ = exit_tx.send(Err(error));
}

// this is the main used for local builds, not in docker container.
#[cfg(feature = "localbuild")]
fn main() {
    logger::init();

    println!("Running local debug build.  NOT for docker image\n");

    let config = get_config();

    let (exit_tx, exit_rx) = channel();

    thread::spawn(move || { process_network_commands2(&config, &exit_tx); });

    match exit_rx.recv() {
        Ok(result) => {
            match result {
                Err(reason) => error!("{}", reason),
                Ok(_) => info!("Connection successfully established"),
            }
        },
        Err(e) => error!("Exit receiver error: {}", e.description()),
    }
}

// the main used for the docker container in production
#[cfg(not(feature = "localbuild"))]
fn main() {
    logger::init();

    println!("Running production docker image\n");

    let config = get_config();

    start_network_manager_service();

    handle_existing_wifi_connections(config.clear, &config.interface);

    let (exit_tx, exit_rx) = channel();

    thread::spawn(move || { process_network_commands(&config, &exit_tx); });

    match exit_rx.recv() {
        Ok(result) => {
            match result {
                Err(reason) => error!("{}", reason),
                Ok(_) => info!("Connection successfully established"),
            }
        },
        Err(e) => error!("Exit receiver error: {}", e.description()),
    }
}
