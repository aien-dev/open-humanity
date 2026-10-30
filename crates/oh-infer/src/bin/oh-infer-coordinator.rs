//! `oh-infer-coordinator`: Drake's side of volunteer inference.
//!
//! oh-infer-coordinator --model-id <id> --model-digest <hex>
//!     [--engine-digest <hex>] [--system-prompt-file <path>]
//!     [--approve <hex>]... [--approved-file <path>]
//!     [--listen-volunteers 127.0.0.1:18136] [--listen-api 127.0.0.1:18137]
//!     [--state-dir <dir>] [--key-from-vault <NAME> [--vault-bin <path>]]
//!     [--sample-rate 0.1] [--probation-sample-rate 0.5] [--probation-jobs 20]
//!     [--max-jobs-per-hour 60] [--max-tokens 1024] [--routing off|on]
//! oh-infer-coordinator reinstate --state-dir <dir> <hex>
//!
//! Both listeners must be loopback; nginx terminates TLS for volunteers and
//! exposes the API to the gateway's tailnet address only. Routing is off
//! unless `--routing on` is given: while off, every overflow request gets
//! 503 and no visitor text reaches a volunteer.

use beacon_core::Keypair;
use oh_core::{keypair_from_vault, parse_key};
use oh_infer::coordinator::{
    Coordinator, CoordinatorConfig, DEFAULT_API_LISTEN, DEFAULT_VOLUNTEER_LISTEN,
};
use oh_infer::protocol::hex;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;

fn fail(msg: &str) -> ExitCode {
    eprintln!("oh-infer-coordinator: {msg}");
    ExitCode::from(2)
}

fn loopback_listener(addr: &str) -> Result<TcpListener, String> {
    let a: SocketAddr = addr.parse().map_err(|_| format!("bad address {addr}"))?;
    if !a.ip().is_loopback() {
        return Err(format!(
            "{addr} is not loopback; put nginx in front instead"
        ));
    }
    TcpListener::bind(a).map_err(|e| format!("{addr}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("reinstate") {
        let (Some(flag), Some(dir), Some(key)) = (args.get(1), args.get(2), args.get(3)) else {
            return fail("reinstate --state-dir <dir> <hex>");
        };
        let Some(key) = parse_key(key).filter(|_| flag == "--state-dir") else {
            return fail("reinstate --state-dir <dir> <hex>");
        };
        let mut cfg = CoordinatorConfig::new("-", [0; 32]);
        cfg.state_dir = Some(PathBuf::from(dir));
        return match Coordinator::new(cfg, Keypair::generate()) {
            Ok(c) if c.reinstate(&key) => {
                println!("reinstated {}", hex(&key));
                ExitCode::SUCCESS
            }
            Ok(_) => fail("that key is not suspended"),
            Err(e) => fail(&e),
        };
    }
    let mut cfg = CoordinatorConfig::new("", [0; 32]);
    let mut have_digest = false;
    let mut listen_v = DEFAULT_VOLUNTEER_LISTEN.to_string();
    let mut listen_a = DEFAULT_API_LISTEN.to_string();
    let mut vault: Option<String> = None;
    let mut vault_bin = PathBuf::from("atlas-vault");
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let Some(v) = it.next() else {
            return fail(&format!("{a} needs a value"));
        };
        let num = |v: &str| v.parse::<f64>().map_err(|_| format!("{a}: not a number"));
        let r: Result<(), String> = (|| {
            match a.as_str() {
                "--model-id" => cfg.model_id = v.clone(),
                "--model-digest" => {
                    cfg.model_digest = parse_key(&v).ok_or("--model-digest: 64 hex")?;
                    have_digest = true;
                }
                "--engine-digest" => {
                    cfg.engine_digest = Some(parse_key(&v).ok_or("--engine-digest: 64 hex")?)
                }
                "--system-prompt-file" => {
                    cfg.system_prompt =
                        Some(std::fs::read_to_string(&v).map_err(|e| format!("{v}: {e}"))?)
                }
                "--approve" => {
                    cfg.approved
                        .insert(parse_key(&v).ok_or("--approve: 64 hex")?);
                }
                "--approved-file" => cfg.approved_file = Some(PathBuf::from(&v)),
                "--listen-volunteers" => listen_v = v.clone(),
                "--listen-api" => listen_a = v.clone(),
                "--state-dir" => cfg.state_dir = Some(PathBuf::from(&v)),
                "--key-from-vault" => vault = Some(v.clone()),
                "--vault-bin" => vault_bin = PathBuf::from(&v),
                "--sample-rate" => cfg.sample_rate = num(&v)?,
                "--probation-sample-rate" => cfg.probation_sample_rate = num(&v)?,
                "--probation-jobs" => cfg.probation_jobs = num(&v)? as u64,
                "--max-jobs-per-hour" => cfg.max_jobs_per_hour = num(&v)? as usize,
                "--max-tokens" => cfg.max_tokens_cap = num(&v)? as u32,
                "--routing" => {
                    cfg.routing_enabled = match v.as_str() {
                        "on" => true,
                        "off" => false,
                        _ => return Err("--routing on|off".into()),
                    }
                }
                _ => return Err(format!("unknown option {a}")),
            }
            Ok(())
        })();
        if let Err(e) = r {
            return fail(&e);
        }
    }
    if cfg.model_id.is_empty() || !have_digest {
        return fail("--model-id and --model-digest are required");
    }
    if !(0.0..=1.0).contains(&cfg.sample_rate) || !(0.0..=1.0).contains(&cfg.probation_sample_rate)
    {
        return fail("sample rates are between 0 and 1");
    }
    let keypair = match vault {
        Some(name) => match keypair_from_vault(&vault_bin, &name) {
            Ok(k) => k,
            Err(e) => return fail(&e),
        },
        None => Keypair::generate(),
    };
    let (lv, la) = match (loopback_listener(&listen_v), loopback_listener(&listen_a)) {
        (Ok(v), Ok(a)) => (v, a),
        (Err(e), _) | (_, Err(e)) => return fail(&e),
    };
    let routing = cfg.routing_enabled;
    let coord = match Coordinator::new(cfg, keypair) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    println!("coordinator key {}", hex(&coord.public_key()));
    println!(
        "volunteers on {listen_v}, gateway API on {listen_a}, routing {}",
        if routing { "ON" } else { "off" }
    );
    let api = coord.clone();
    std::thread::spawn(move || api.serve_api(la));
    coord.serve_volunteers(lv);
    ExitCode::SUCCESS
}
