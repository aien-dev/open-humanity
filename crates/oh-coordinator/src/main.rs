//! `oh-coordinator`: hand out work units, score updates in Turings, and keep
//! the ones that help.
//!
//! Usage: oh-coordinator --corpus <file> [--listen <addr>] [--rounds <n>]
//!        [--volunteers-per-round <n>] [--steps <n>] [--heldout-fraction <f>]
//!        [--seed <n>] [--ledger <path>] [--dim <n>] [--baseline]
//!
//! `--baseline` trains the same shards for the same total steps in this one
//! process, with no network, and prints the same held-out measurements.

use oh_coordinator::{baseline, Coordinator, Settings, DEFAULT_LISTEN};
use oh_core::Ledger;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    corpus: PathBuf,
    listen: String,
    rounds: u32,
    ledger: PathBuf,
    baseline: bool,
    settings: Settings,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        corpus: PathBuf::new(),
        listen: DEFAULT_LISTEN.into(),
        rounds: 3,
        ledger: PathBuf::from("oh-ledger.jsonl"),
        baseline: false,
        settings: Settings {
            volunteers_per_round: 2,
            steps: 200,
            heldout_fraction: 0.1,
            seed: 1,
            dim: 32,
        },
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--baseline" {
            args.baseline = true;
            continue;
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        let bad = || format!("bad value for {flag}: {value}");
        let s = &mut args.settings;
        match flag.as_str() {
            "--corpus" => args.corpus = PathBuf::from(&value),
            "--listen" => args.listen = value.clone(),
            "--rounds" => args.rounds = value.parse().map_err(|_| bad())?,
            "--ledger" => args.ledger = PathBuf::from(&value),
            "--volunteers-per-round" => {
                s.volunteers_per_round = value.parse().map_err(|_| bad())?
            }
            "--steps" => s.steps = value.parse().map_err(|_| bad())?,
            "--heldout-fraction" => s.heldout_fraction = value.parse().map_err(|_| bad())?,
            "--seed" => s.seed = value.parse().map_err(|_| bad())?,
            "--dim" => s.dim = value.parse().map_err(|_| bad())?,
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

    if args.baseline {
        let bpb = baseline(&corpus, &args.settings, args.rounds)?;
        println!("baseline start heldout_bpb={:.4}", bpb[0]);
        for (round, v) in bpb.iter().enumerate().skip(1) {
            println!("round={round} heldout_bpb={v:.4}");
        }
        println!("final_heldout_bpb={:.4}", bpb[bpb.len() - 1]);
        return Ok(());
    }

    let ledger = Ledger::open(&args.ledger)
        .map_err(|e| format!("cannot open ledger {}: {e}", args.ledger.display()))?;
    let mut coordinator = Coordinator::new(&corpus, &args.settings, ledger)?;
    let listener = TcpListener::bind(&args.listen)
        .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
    println!("coordinator key {}", hex(&coordinator.pubkey()));
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
