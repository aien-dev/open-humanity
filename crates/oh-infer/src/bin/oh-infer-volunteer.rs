//! `oh-infer-volunteer`: lend this Spark's engine to answer Allen's visitors
//! when Drake's Spark is busy. Outbound only: it opens no listening socket.
//!
//! oh-infer-volunteer init --key-file <path>
//! oh-infer-volunteer print-key (--key-file <path> | --key-from-vault <NAME> [--vault-bin <path>])
//! oh-infer-volunteer verify --manifest <path> --model-dir <dir> [--model-digest <hex>]
//! oh-infer-volunteer pause --pause-file <path>
//! oh-infer-volunteer resume --pause-file <path>
//! oh-infer-volunteer run --coordinator <https://host/path> --coordinator-key <hex>
//!     (--key-file <path> | --key-from-vault <NAME> [--vault-bin <path>])
//!     --manifest <path> --model-dir <dir> --model-digest <hex>
//!     [--engine <127.0.0.1:port>] [--engine-bin <path>] [--pause-file <path>] [--once]
//!
//! Any command takes `--config <file>`: `name value` lines for the same
//! options (without `--`); options given on the command line win.
//!
//! Exit: 0 done, 2 usage, 3 suspended, 4 refused by the coordinator,
//! 5 model or engine check failed, 6 key error, 7 connection failed (--once).

use beacon_core::Keypair;
use oh_core::{keypair_from_seed_hex, keypair_from_vault, parse_key};
use oh_infer::engine::{HttpEngine, DEFAULT_ENGINE_ADDR};
use oh_infer::model::{sha256_file, verify_model};
use oh_infer::protocol::hex;
use oh_infer::tls::Endpoint;
use oh_infer::volunteer::{run_session, VolunteerConfig, VolunteerError};
use rand::RngCore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

fn usage(msg: &str) -> ExitCode {
    eprintln!("oh-infer-volunteer: {msg}\nsee the comment at the top of oh-infer-volunteer.rs or docs/design/volunteer-inference-v0.md");
    ExitCode::from(2)
}

fn parse(args: &[String]) -> Result<(HashMap<String, String>, bool), String> {
    let mut map = HashMap::new();
    let mut once = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--once" {
            once = true;
            continue;
        }
        let Some(name) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument {a:?}"));
        };
        let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
        map.insert(name.to_string(), v.clone());
    }
    // `--config FILE`: one `name value` per line (# comments). Options on the
    // command line win. The SI bundle ships the coordinator URL, its key and
    // the model digest this way, inside the signed release.
    if let Some(path) = map.get("config").cloned() {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| format!("{path}: line {line:?} needs a name and a value"))?;
            map.entry(k.to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    Ok((map, once))
}

#[cfg(unix)]
fn private_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if m.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is readable by other users; run: chmod 600 {}",
            path.display(),
            path.display()
        ));
    }
    Ok(())
}

fn load_key(o: &HashMap<String, String>) -> Result<Keypair, String> {
    if let Some(name) = o.get("key-from-vault") {
        let bin = PathBuf::from(o.get("vault-bin").map_or("atlas-vault", String::as_str));
        return keypair_from_vault(&bin, name);
    }
    let path = Path::new(
        o.get("key-file")
            .ok_or("give --key-file or --key-from-vault")?,
    );
    private_mode(path)?;
    let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    keypair_from_seed_hex(&text)
}

fn init(o: &HashMap<String, String>) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(o.get("key-file").ok_or("init needs --key-file")?);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let kp = Keypair::from_seed(&seed);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            format!(
                "{}: {e} (an existing key is never overwritten)",
                path.display()
            )
        })?;
    let mut text = hex(&seed);
    seed.fill(0);
    text.push('\n');
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    // Overwrite the in-memory copy of the hex seed.
    let mut bytes = text.into_bytes();
    bytes.fill(0);
    println!("volunteer key {}", hex(&kp.pubkey_bytes()));
    Ok(())
}

fn digest_arg(o: &HashMap<String, String>, name: &str) -> Result<Option<[u8; 32]>, String> {
    match o.get(name) {
        None => Ok(None),
        Some(h) => parse_key(h)
            .map(Some)
            .ok_or_else(|| format!("--{name} must be 64 hex characters")),
    }
}

fn main() -> ExitCode {
    let all: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = all.first().cloned() else {
        return usage("give a command: init, print-key, verify, pause, resume or run");
    };
    let (o, once) = match parse(&all[1..]) {
        Ok(x) => x,
        Err(e) => return usage(&e),
    };
    match cmd.as_str() {
        "init" => match init(&o) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("oh-infer-volunteer: {e}");
                ExitCode::from(6)
            }
        },
        "print-key" => match load_key(&o) {
            Ok(kp) => {
                println!("volunteer key {}", hex(&kp.pubkey_bytes()));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("oh-infer-volunteer: {e}");
                ExitCode::from(6)
            }
        },
        "pause" | "resume" => {
            let Some(p) = o.get("pause-file") else {
                return usage("needs --pause-file");
            };
            let r = if cmd == "pause" {
                std::fs::write(p, b"paused by the owner\n")
            } else {
                match std::fs::remove_file(p) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    r => r,
                }
            };
            match r {
                Ok(()) => {
                    println!(
                        "lending {}",
                        if cmd == "pause" { "paused" } else { "resumed" }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("oh-infer-volunteer: {p}: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "verify" => {
            let (Some(m), Some(d)) = (o.get("manifest"), o.get("model-dir")) else {
                return usage("verify needs --manifest and --model-dir");
            };
            let pinned = match digest_arg(&o, "model-digest") {
                Ok(p) => p,
                Err(e) => return usage(&e),
            };
            match verify_model(Path::new(m), Path::new(d), pinned.as_ref()) {
                Ok(v) => {
                    println!(
                        "model {} verified: {} files, {} bytes, manifest sha256 {}",
                        v.name,
                        v.files,
                        v.bytes,
                        hex(&v.digest)
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("oh-infer-volunteer: model check failed: {e}");
                    ExitCode::from(5)
                }
            }
        }
        "run" => run(&o, once),
        _ => usage(&format!("unknown command {cmd:?}")),
    }
}

fn run(o: &HashMap<String, String>, once: bool) -> ExitCode {
    let need = [
        "coordinator",
        "coordinator-key",
        "manifest",
        "model-dir",
        "model-digest",
    ];
    if let Some(n) = need.iter().find(|n| !o.contains_key(**n)) {
        return usage(&format!("run needs --{n}"));
    }
    let endpoint = match Endpoint::parse(&o["coordinator"]) {
        Ok(e) => e,
        Err(e) => return usage(&e),
    };
    let Some(coordinator_key) = parse_key(&o["coordinator-key"]) else {
        return usage("--coordinator-key must be 64 hex characters");
    };
    let pinned = match digest_arg(o, "model-digest") {
        Ok(p) => p.expect("checked above"),
        Err(e) => return usage(&e),
    };
    let keypair = match load_key(o) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("oh-infer-volunteer: {e}");
            return ExitCode::from(6);
        }
    };
    eprintln!("oh-infer-volunteer: checking every model file against the pinned manifest");
    let model = match verify_model(
        Path::new(&o["manifest"]),
        Path::new(&o["model-dir"]),
        Some(&pinned),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("oh-infer-volunteer: refusing to serve: {e}");
            return ExitCode::from(5);
        }
    };
    let engine_digest = match o.get("engine-bin") {
        Some(p) => match sha256_file(Path::new(p)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("oh-infer-volunteer: refusing to serve: {e}");
                return ExitCode::from(5);
            }
        },
        None => [0u8; 32],
    };
    let cfg = VolunteerConfig {
        keypair,
        coordinator_key,
        host: endpoint.host.clone(),
        path: endpoint.path.clone(),
        model_id: model.name.clone(),
        model_digest: model.digest,
        engine_digest,
        pause_file: o.get("pause-file").map(PathBuf::from),
    };
    let engine = HttpEngine::new(o.get("engine").map_or(DEFAULT_ENGINE_ADDR, String::as_str));
    eprintln!(
        "oh-infer-volunteer: model {} verified; key {}; connecting to {}:{} (outbound only)",
        model.name,
        hex(&cfg.keypair.pubkey_bytes()),
        endpoint.host,
        endpoint.port
    );
    let mut backoff = Duration::from_secs(5);
    loop {
        let result = endpoint
            .connect(Duration::from_secs(20))
            .map_err(VolunteerError::Io)
            .and_then(|conn| {
                run_session(conn, &cfg, &engine, &mut |line| {
                    eprintln!("oh-infer-volunteer: {line}")
                })
            });
        match result {
            Ok(r) => {
                eprintln!(
                    "oh-infer-volunteer: session closed after {} replies ({} failed)",
                    r.answered, r.failed
                );
                backoff = Duration::from_secs(5);
            }
            Err(VolunteerError::Suspended(r)) => {
                eprintln!("oh-infer-volunteer: suspended: {r}");
                return ExitCode::from(3);
            }
            Err(e @ VolunteerError::Refused(_)) => {
                eprintln!("oh-infer-volunteer: {e}");
                return ExitCode::from(4);
            }
            Err(e @ VolunteerError::ModelMismatch { .. }) => {
                eprintln!("oh-infer-volunteer: {e}");
                return ExitCode::from(5);
            }
            Err(e) => {
                eprintln!(
                    "oh-infer-volunteer: {e}; retrying in {}s",
                    backoff.as_secs()
                );
                if once {
                    return ExitCode::from(7);
                }
            }
        }
        if once {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(300));
    }
}
