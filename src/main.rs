//! A split-DNS forwarder with validated routing and bounded UDP/TCP workers.
//!
//! Startup converts configuration into routing policy before opening listeners.
//! [`forwarding`] coordinates requests; [`dns`] owns protocol invariants and
//! [`upstream`] owns exchanges with resolvers. [`server`] owns client I/O and
//! service shutdown.

#![forbid(unsafe_code)]

mod config;
mod dns;
mod forwarding;
mod logging;
mod routing;
mod server;
mod transport;
mod upstream;

use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(io::stderr().lock(), "ERROR {message}");
            ExitCode::FAILURE
        }
    }
}

/// Handles CLI-only exits, validates configuration and runs the service.
///
/// Errors acquire operation and path context here before `main` reports them.
fn run() -> Result<(), String> {
    // Keep paths as OS strings so non-UTF-8 configuration paths remain usable.
    let mut args = std::env::args_os().skip(1);
    let mut path = PathBuf::from(config::DEFAULT_CONFIG);
    let mut seen_config = false;
    let mut check = false;
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            let _ = writeln!(
                io::stdout().lock(),
                "Sederial {}\nUsage: sederial [--config PATH] [--check]\n\nDefault config: {}\n--check validates configuration without opening listeners.\nUse SIGTERM or SIGINT for graceful shutdown.",
                env!("CARGO_PKG_VERSION"),
                config::DEFAULT_CONFIG
            );
            return Ok(());
        } else if arg == "--version" || arg == "-V" {
            let _ = writeln!(
                io::stdout().lock(),
                "sederial {}",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        } else if arg == "--config" && !seen_config {
            path = args
                .next()
                .map(PathBuf::from)
                .ok_or("--config requires a path")?;
            seen_config = true;
        } else if arg == "--check" && !check {
            check = true;
        } else {
            return Err(format!("unknown or repeated argument {arg:?}; use --help"));
        }
    }
    let config = config::Config::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    logging::info(format_args!("configuration loaded from {}", path.display()));
    logging::info(format_args!(
        "default: {} upstream(s)",
        config.routing.default().servers().len()
    ));
    let routes = config.routing.routes();
    logging::info(format_args!("{} route(s)", routes.len()));
    // Lookup order is longest suffix first. Cap the lines so a full split-DNS
    // file cannot write one journal entry per route.
    const ROUTE_LOG_LIMIT: usize = 8;
    for route in routes.iter().take(ROUTE_LOG_LIMIT) {
        logging::info(format_args!(
            "route {}: {} upstream(s)",
            route.suffix,
            route.upstreams.servers().len()
        ));
    }
    if routes.len() > ROUTE_LOG_LIMIT {
        logging::info(format_args!(
            "{} additional route(s) omitted from startup log",
            routes.len() - ROUTE_LOG_LIMIT
        ));
    }
    if check {
        logging::info(format_args!("configuration valid"));
        return Ok(());
    }
    let stop = Arc::new(AtomicBool::new(false));
    // Signal handlers only set a flag; ordinary threads perform I/O and cleanup.
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| format!("register shutdown signal: {e}"))?;
    }
    let server = server::Server::bind(config).map_err(|e| format!("bind DNS listeners: {e}"))?;
    server.run(stop).map_err(|e| format!("DNS service: {e}"))
}
