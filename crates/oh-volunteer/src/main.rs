//! `oh-volunteer`: lend this machine's time to train the shared model.
//!
//! Usage: oh-volunteer --coordinator <addr> --key-from-vault <NAME>
//!        [--vault-bin <path>] [--rounds <n>] [--seed <n>]
//!        [--keep <fraction>] (--coordinator-key <hex> | --trust-first-use)
//!
//!        oh-volunteer teach --coordinator <addr> --key-from-vault <NAME>
//!        [--teacher <host:port>] [--model <id>] [--batches <n>]
//!        [--max-tokens <n>] [--seed <n>]
//!        (--coordinator-key <hex> | --trust-first-use)
//!
//!        oh-volunteer --print-key --key-from-vault <NAME> [--vault-bin <path>]
//!
//! Every connection is encrypted (`oh_core::volunteer_handshake`). The
//! coordinator must prove it holds `--coordinator-key` (printed by
//! oh-coordinator at start as "coordinator key <hex>"). Without that key the
//! volunteer refuses to connect unless `--trust-first-use` is given, which
//! accepts the first key seen, prints a warning, and pins it for the rest
//! of the run.
//!
//! `teach` asks a language model running on this machine (default
//! 127.0.0.1:18091; the model id is read from its /v1/models unless
//! `--model` is given) to write teaching text, runs the text through the
//! Personal Data Firewall, and sends only the firewalled text.

use beacon_core::Keypair;
use oh_core::{
    discover_model, keypair_from_vault, parse_key, volunteer_handshake, CoordinatorPin,
    EncryptedStream, LocalHttpTeacher,
};
use oh_volunteer::{
    run_once, summary_line, teach_once, teach_summary_line, Settings, VolunteerError,
    DEFAULT_KEEP_FRACTION, DEFAULT_TEACHER_ADDR, DEFAULT_TEACH_MAX_TOKENS,
};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

struct Args {
    coordinator: String,
    /// Rounds in training mode, batches in teaching mode.
    rounds: u32,
    settings: Settings,
    teach: Option<TeachArgs>,
    trust_first_use: bool,
    key_from_vault: Option<String>,
    vault_bin: PathBuf,
    print_key: bool,
}

struct TeachArgs {
    teacher: String,
    model: Option<String>,
    max_tokens: u32,
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
        teach: None,
        trust_first_use: false,
        key_from_vault: None,
        vault_bin: PathBuf::from("atlas-vault"),
        print_key: false,
    };
    let mut it = std::env::args().skip(1).peekable();
    if it.peek().map(String::as_str) == Some("teach") {
        it.next();
        args.teach = Some(TeachArgs {
            teacher: DEFAULT_TEACHER_ADDR.into(),
            model: None,
            max_tokens: DEFAULT_TEACH_MAX_TOKENS,
        });
    }
    while let Some(flag) = it.next() {
        if flag == "--trust-first-use" {
            args.trust_first_use = true;
            continue;
        }
        if flag == "--print-key" {
            args.print_key = true;
            continue;
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        let bad = || format!("bad value for {flag}: {value}");
        match (flag.as_str(), args.teach.as_mut()) {
            ("--key-from-vault", _) => args.key_from_vault = Some(value),
            ("--vault-bin", _) => args.vault_bin = PathBuf::from(value),
            ("--coordinator", _) => args.coordinator = value,
            ("--rounds", None) | ("--batches", Some(_)) => {
                args.rounds = value.parse().map_err(|_| bad())?
            }
            ("--seed", _) => args.settings.seed = value.parse().map_err(|_| bad())?,
            ("--keep", None) => {
                let f: f64 = value.parse().map_err(|_| bad())?;
                if !(f > 0.0 && f <= 1.0) {
                    return Err(bad());
                }
                args.settings.keep_fraction = f;
            }
            ("--coordinator-key", _) => {
                args.settings.coordinator_key = Some(parse_key(&value).ok_or_else(bad)?)
            }
            ("--teacher", Some(t)) => t.teacher = value,
            ("--model", Some(t)) => t.model = Some(value),
            ("--max-tokens", Some(t)) => {
                t.max_tokens = value.parse().map_err(|_| bad())?;
                if t.max_tokens == 0 {
                    return Err(bad());
                }
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if args.key_from_vault.is_none() {
        return Err("--key-from-vault <NAME> is required for an approved identity".into());
    }
    if args.print_key {
        return Ok(args);
    }
    if args.coordinator.is_empty() {
        return Err("--coordinator <addr> is required".into());
    }
    if args.settings.coordinator_key.is_none() && !args.trust_first_use {
        return Err("refusing to connect without the coordinator's key: pass \
                    --coordinator-key <hex> (oh-coordinator prints it at start as \
                    \"coordinator key <hex>\"), or --trust-first-use to accept the first \
                    key seen"
            .into());
    }
    Ok(args)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Connects and opens the encrypted transport. Pinned to
/// `--coordinator-key`, or to the key accepted on first use; after the
/// first connection the key is kept, so work units signed by any other key
/// are refused as well.
fn open(args: &mut Args, keypair: &Keypair) -> Result<EncryptedStream<TcpStream>, String> {
    let stream = connect(&args.coordinator)?;
    let pin = match args.settings.coordinator_key {
        Some(key) => CoordinatorPin::Key(key),
        None => CoordinatorPin::TrustFirstUse,
    };
    let secure = volunteer_handshake(stream, keypair, pin)
        .map_err(|e| format!("secure connection to {} failed: {e}", args.coordinator))?;
    if pin == CoordinatorPin::TrustFirstUse {
        let key = hex(&secure.peer_identity());
        eprintln!(
            "WARNING: trusting coordinator key {key} on first use. Anyone between this \
             machine and the coordinator could have supplied it. Check it against the \
             coordinator's \"coordinator key\" line and pass --coordinator-key {key} next time."
        );
    }
    args.settings.coordinator_key = Some(secure.peer_identity());
    Ok(secure)
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

fn train(args: &mut Args, keypair: &Keypair) -> ExitCode {
    for _ in 0..args.rounds {
        let result = open(args, keypair).and_then(|mut stream| {
            run_once(&mut stream, keypair, &args.settings).map_err(|e| e.to_string())
        });
        match result {
            Ok(outcome) => println!("{}", summary_line(&outcome)),
            Err(e) => {
                eprintln!("oh-volunteer: work unit failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn teach(args: &mut Args, keypair: &Keypair) -> ExitCode {
    let t = args.teach.as_ref().expect("teach mode");
    let model = match &t.model {
        Some(m) => m.clone(),
        None => match discover_model(&t.teacher) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("oh-volunteer: cannot find a model at {}: {e}", t.teacher);
                return ExitCode::FAILURE;
            }
        },
    };
    println!("Teacher: {model} at {}", t.teacher);
    let teacher = LocalHttpTeacher::new(&t.teacher, &model);
    let max_tokens = t.max_tokens;
    for batch in 1..=args.rounds {
        let mut stream = match open(args, keypair) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("oh-volunteer: {e}");
                return ExitCode::FAILURE;
            }
        };
        match teach_once(&mut stream, keypair, &args.settings, &teacher, max_tokens) {
            Ok(outcome) => println!("{}", teach_summary_line(batch, &outcome)),
            // A refusal is this batch's answer, not a failure of the run.
            Err(e @ (VolunteerError::Firewall(_) | VolunteerError::EmptyTeaching)) => {
                println!("Batch {batch}: not sent, {e}");
            }
            Err(e) => {
                eprintln!("oh-volunteer: teaching batch {batch} failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mut args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("oh-volunteer: {e}");
            return ExitCode::from(2);
        }
    };
    let keypair = match keypair_from_vault(
        &args.vault_bin,
        args.key_from_vault
            .as_deref()
            .expect("validated vault name"),
    ) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("oh-volunteer: {e}");
            return ExitCode::FAILURE;
        }
    };
    if args.print_key {
        println!("volunteer key {}", hex(&keypair.pubkey_bytes()));
        return ExitCode::SUCCESS;
    }
    if args.teach.is_some() {
        teach(&mut args, &keypair)
    } else {
        train(&mut args, &keypair)
    }
}
