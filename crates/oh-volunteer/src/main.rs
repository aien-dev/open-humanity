//! `oh-volunteer`: lend this machine's time to train the shared model.
//!
//! Usage: oh-volunteer --coordinator <addr> [--rounds <n>] [--seed <n>]
//!        [--keep <fraction>] [--coordinator-key <hex>]

use beacon_core::Keypair;
use oh_volunteer::{parse_key, run_once, summary_line, Settings, DEFAULT_KEEP_FRACTION};
use std::net::TcpStream;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

struct Args {
    coordinator: String,
    rounds: u32,
    settings: Settings,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        coordinator: String::new(),
        rounds: 1,
        settings: Settings {
            seed: 1,
            keep_fraction: DEFAULT_KEEP_FRACTION,
            coordinator_key: None,
        },
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        let bad = || format!("bad value for {flag}: {value}");
        match flag.as_str() {
            "--coordinator" => args.coordinator = value,
            "--rounds" => args.rounds = value.parse().map_err(|_| bad())?,
            "--seed" => args.settings.seed = value.parse().map_err(|_| bad())?,
            "--keep" => {
                let f: f64 = value.parse().map_err(|_| bad())?;
                if !(f > 0.0 && f <= 1.0) {
                    return Err(bad());
                }
                args.settings.keep_fraction = f;
            }
            "--coordinator-key" => {
                args.settings.coordinator_key = Some(parse_key(&value).ok_or_else(bad)?)
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if args.coordinator.is_empty() {
        return Err("--coordinator <addr> is required".into());
    }
    Ok(args)
}

/// The coordinator may not be listening yet; keep trying for a minute.
fn connect(addr: &str) -> Result<TcpStream, String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(600)))
                    .map_err(|e| e.to_string())?;
                return Ok(stream);
            }
            Err(e) if Instant::now() >= deadline => {
                return Err(format!("could not reach coordinator at {addr}: {e}"))
            }
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
}

fn main() -> ExitCode {
    let mut args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("oh-volunteer: {e}");
            return ExitCode::from(2);
        }
    };
    // The key lives only in memory and is gone when the process exits.
    let keypair = Keypair::generate();
    for _ in 0..args.rounds {
        let result = connect(&args.coordinator).and_then(|mut stream| {
            run_once(&mut stream, &keypair, &args.settings).map_err(|e| e.to_string())
        });
        match result {
            Ok(outcome) => {
                println!("{}", summary_line(&outcome));
                // Trust the first coordinator key seen for the rest of the run.
                args.settings.coordinator_key = Some(outcome.coordinator_key);
            }
            Err(e) => {
                eprintln!("oh-volunteer: work unit failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
