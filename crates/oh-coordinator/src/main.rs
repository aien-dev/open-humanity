//! `oh-coordinator`: hand out work units, score updates in Turings, and keep
//! the ones that help.
//!
//! Usage: oh-coordinator --corpus <file> [--listen <addr>] [--rounds <n>]
//!        [--volunteers-per-round <n>] [--steps <n>] [--heldout-fraction <f>]
//!        [--seed <n>] [--ledger <path>] [--dim <n>] [--outer-lr <f>]
//!        [--baseline | --simulate [--keep-fraction <f>] [--no-compression]
//!        [--no-update-gate] [--shard-order fixed|rotate]]
//!        [--key-from-vault <NAME> [--vault-bin <path>]]
//!
//! `--baseline` trains the same shards for the same total steps in this one
//! process, with no network, and prints the same held-out measurements.
//! `--simulate` runs the volunteer protocol (train each shard from the
//! round's base, compress, score gate, aggregate) in this one process, so
//! each knob can be changed on its own and runs repeat exactly.
//!
//! The coordinator signs with a fresh key each start unless
//! `--key-from-vault <NAME>` is given: then it runs `atlas-vault get <NAME>`
//! (or `--vault-bin <path> get <NAME>`), reads a 64 hex character seed from
//! its output into memory, and signs with the same key on every start, so
//! volunteers pin it once. The seed is never written to disk or printed.

use beacon_core::Keypair;
use oh_coordinator::identity::keypair_from_vault;
use oh_coordinator::{
    baseline, simulate, Coordinator, Settings, ShardOrder, SimOptions, DEFAULT_LISTEN,
    DEFAULT_OUTER_LR,
};
use oh_core::Ledger;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;

enum Mode {
    Serve,
    Baseline,
    Simulate,
}

struct Args {
    corpus: PathBuf,
    listen: String,
    rounds: u32,
    ledger: PathBuf,
    mode: Mode,
    settings: Settings,
    sim: SimOptions,
    key_from_vault: Option<String>,
    vault_bin: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        corpus: PathBuf::new(),
        listen: DEFAULT_LISTEN.into(),
        rounds: 3,
        ledger: PathBuf::from("oh-ledger.jsonl"),
        mode: Mode::Serve,
        settings: Settings {
            volunteers_per_round: 2,
            steps: 200,
            heldout_fraction: 0.1,
            seed: 1,
            dim: 32,
            outer_lr: DEFAULT_OUTER_LR,
        },
        sim: SimOptions::default(),
        key_from_vault: None,
        vault_bin: PathBuf::from("atlas-vault"),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--baseline" => {
                args.mode = Mode::Baseline;
                continue;
            }
            "--simulate" => {
                args.mode = Mode::Simulate;
                continue;
            }
            "--no-compression" => {
                args.sim.compress = false;
                continue;
            }
            "--no-update-gate" => {
                args.sim.update_gate = false;
                continue;
            }
            _ => {}
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        let bad = || format!("bad value for {flag}: {value}");
        let s = &mut args.settings;
        match flag.as_str() {
            "--corpus" => args.corpus = PathBuf::from(&value),
            "--listen" => args.listen = value.clone(),
            "--rounds" => args.rounds = value.parse().map_err(|_| bad())?,
            "--ledger" => args.ledger = PathBuf::from(&value),
            "--key-from-vault" => args.key_from_vault = Some(value.clone()),
            "--vault-bin" => args.vault_bin = PathBuf::from(&value),
            "--volunteers-per-round" => {
                s.volunteers_per_round = value.parse().map_err(|_| bad())?
            }
            "--steps" => s.steps = value.parse().map_err(|_| bad())?,
            "--heldout-fraction" => s.heldout_fraction = value.parse().map_err(|_| bad())?,
            "--seed" => s.seed = value.parse().map_err(|_| bad())?,
            "--dim" => s.dim = value.parse().map_err(|_| bad())?,
            "--outer-lr" => s.outer_lr = value.parse().map_err(|_| bad())?,
            "--keep-fraction" => args.sim.keep_fraction = value.parse().map_err(|_| bad())?,
            "--shard-order" => {
                args.sim.shard_order = match value.as_str() {
                    "fixed" => ShardOrder::Fixed,
                    "rotate" => ShardOrder::Rotate,
                    _ => return Err(bad()),
                }
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if args.corpus.as_os_str().is_empty() {
        return Err("--corpus <file> is required".into());
    }
    Ok(args)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(args: Args) -> Result<(), String> {
    let corpus = std::fs::read(&args.corpus)
        .map_err(|e| format!("cannot read {}: {e}", args.corpus.display()))?;

    match args.mode {
        Mode::Baseline => {
            let bpb = baseline(&corpus, &args.settings, args.rounds)?;
            println!("baseline start heldout_bpb={:.4}", bpb[0]);
            for (round, v) in bpb.iter().enumerate().skip(1) {
                println!("round={round} heldout_bpb={v:.4}");
            }
            println!("final_heldout_bpb={:.4}", bpb[bpb.len() - 1]);
            return Ok(());
        }
        Mode::Simulate => {
            let result = simulate(&corpus, &args.settings, args.rounds, &args.sim)?;
            let sim = &args.sim;
            println!(
                "simulate volunteers={} steps={} outer_lr={} keep_fraction={} compress={} update_gate={} shard_order={:?}",
                args.settings.volunteers_per_round,
                args.settings.steps,
                args.settings.outer_lr,
                sim.keep_fraction,
                sim.compress,
                sim.update_gate,
                sim.shard_order
            );
            println!("start heldout_bpb={:.4}", result.start_bpb);
            let mut accepted = 0;
            for report in &result.rounds {
                accepted += report.accepted;
                println!("{}", report.line());
            }
            let last = result
                .rounds
                .last()
                .map_or(result.start_bpb, |r| r.heldout_bpb);
            println!(
                "accepted_updates={accepted} of {}",
                result.rounds.len() * args.settings.volunteers_per_round
            );
            println!("final_heldout_bpb={last:.4}");
            return Ok(());
        }
        Mode::Serve => {}
    }

    let ledger = Ledger::open(&args.ledger)
        .map_err(|e| format!("cannot open ledger {}: {e}", args.ledger.display()))?;
    let (keypair, key_source) = match &args.key_from_vault {
        Some(name) => (
            keypair_from_vault(&args.vault_bin, name)?,
            format!("from atlas-vault entry {name}"),
        ),
        None => (Keypair::generate(), "fresh for this run".to_string()),
    };
    let mut coordinator = Coordinator::with_keypair(&corpus, &args.settings, ledger, keypair)?;
    let listener = TcpListener::bind(&args.listen)
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    println!("coordinator key {}", hex(&coordinator.pubkey()));
    println!("coordinator key source: {key_source}");
    println!(
        "run {} listening on {}: {} training bytes in {} shards, {} held-out bytes sealed",
        hex(&coordinator.run_id()),
        args.listen,
        coordinator.train_len(),
        coordinator.shard_count(),
        coordinator.heldout().len()
    );
    println!("start heldout_bpb={:.4}", coordinator.heldout_bpb());
    coordinator.serve(&listener, args.rounds, |report| {
        println!("{}", report.line())
    })?;
    println!("final_heldout_bpb={:.4}", coordinator.heldout_bpb());
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("oh-coordinator: {e}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oh-coordinator: {e}");
            ExitCode::FAILURE
        }
    }
}
