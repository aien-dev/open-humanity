//! `aienet0-serve`: the Aienet-0 P0 worker. Connects to one coordinator,
//! receives one submitter-signed MJB1 bundle over the pinned encrypted
//! transport, admits only the allowlisted `matmul_u32` job within bounds,
//! refuses a bundle it has seen before, runs it, returns an MJR1 COMPLETED
//! receipt signed by its executor key, and exits. It runs in the foreground
//! and never listens.
//!
//! Usage: aienet0-serve keys --keys DIR
//!        aienet0-serve --connect HOST:PORT --keys DIR --pins DIR --state DIR
//!                      [--connect-timeout SECS]
//!                      [--misbehave wrong-output|tamper-receipt]
//!
//! `--keys DIR`: `transport.seed` (Ed25519 seed, hex) and `executor.p256`
//! (P-256 scalar, hex): test identities, not a wallet.
//! `--pins DIR`: `coordinator.ed25519` (32-byte hex) and `submitter.p256`
//! (33-byte compressed hex), exchanged out of band; no trust on first use.
//! `--state DIR`: `seen` holds every admitted dag_digest (fsync before the
//! job runs), so a replayed bundle is refused even across restarts.
//! `--misbehave` exists only for the negative controls: `wrong-output`
//! signs an output digest with one bit flipped (a dishonest worker);
//! `tamper-receipt` flips one bit of the output digest after signing (a
//! receipt altered in flight).
//!
//! Exit: 0 receipt sent, 2 usage or key files, 10 transport, 11 refused
//! the bundle (refusal sent to the coordinator), 15 local i/o.

use aien_microjob::aienet0::{
    admit_bundle, executor_receipt, from_hex, matmul_u32_digest, public_key, signing_key_from_hex,
    to_hex,
};
use oh_core::carrier::{recv_frame, send_frame, Frame};
use oh_core::{keypair_from_seed_hex, volunteer_handshake, CoordinatorPin};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The admission policy in force; its SHA-256 is the receipt's `policy_hash`.
const POLICY: &str = "AIENET0-WORKER-POLICY-V1 allow=matmul_u32 mjb1.op=MATMUL payload.kind=1 \
dims=1..=256 caps>=job verifier=RECOMPUTE replay=refuse submitter=pinned coordinator=pinned";

struct Fail(u8, String);

fn read_text(p: &Path) -> Result<String, Fail> {
    fs::read_to_string(p).map_err(|e| Fail(2, format!("cannot read {}: {e}", p.display())))
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], flag: &str) -> Result<String, Fail> {
    value(args, flag).ok_or_else(|| Fail(2, format!("missing {flag}")))
}

fn keys(dir: &Path) -> Result<(beacon_core::Keypair, p256::ecdsa::SigningKey), Fail> {
    let transport = keypair_from_seed_hex(read_text(&dir.join("transport.seed"))?.as_bytes())
        .map_err(|e| Fail(2, format!("transport.seed: {e}")))?;
    let exec = signing_key_from_hex(&read_text(&dir.join("executor.p256"))?)
        .ok_or_else(|| Fail(2, "executor.p256 is not a P-256 scalar in hex".into()))?;
    Ok((transport, exec))
}

/// Append `dag` to the seen set unless it is already there. Fsynced before
/// the job runs, so a crash after this point refuses the bundle next time
/// rather than running it twice.
fn mark_seen(state: &Path, dag: &str) -> Result<bool, Fail> {
    let io = |e: std::io::Error| Fail(15, format!("state: {e}"));
    fs::create_dir_all(state).map_err(io)?;
    let path = state.join("seen");
    let seen = fs::read_to_string(&path).unwrap_or_default();
    if seen.lines().any(|l| l == dag) {
        return Ok(false);
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(io)?;
    f.write_all(format!("{dag}\n").as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    Ok(true)
}

fn connect(addr: &str, timeout: Duration) -> Result<TcpStream, Fail> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => {
                return Err(Fail(10, format!("cannot connect to {addr}: {e}")))
            }
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn serve(args: &[String]) -> Result<(), Fail> {
    let (transport, exec) = keys(&PathBuf::from(need(args, "--keys")?))?;
    let pins = PathBuf::from(need(args, "--pins")?);
    let coord = from_hex::<32>(&read_text(&pins.join("coordinator.ed25519"))?)
        .ok_or_else(|| Fail(2, "coordinator.ed25519 is not 32-byte hex".into()))?;
    let submitter = from_hex::<33>(&read_text(&pins.join("submitter.p256"))?)
        .ok_or_else(|| Fail(2, "submitter.p256 is not 33-byte hex".into()))?;
    let state = PathBuf::from(need(args, "--state")?);
    let misbehave = value(args, "--misbehave");
    if let Some(m) = misbehave.as_deref() {
        if m != "wrong-output" && m != "tamper-receipt" {
            return Err(Fail(2, format!("unknown --misbehave {m}")));
        }
        eprintln!("aienet0-serve: *** TEST MODE --misbehave {m}: this worker will lie ***");
    }
    let secs = value(args, "--connect-timeout")
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let addr = need(args, "--connect")?;

    let stream = connect(&addr, Duration::from_secs(secs))?;
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
    let mut s = volunteer_handshake(stream, &transport, CoordinatorPin::Key(coord))
        .map_err(|e| Fail(10, format!("TRANSPORT {e}")))?;
    eprintln!(
        "aienet0-serve: session up, coordinator {}",
        to_hex(&s.peer_identity())
    );
    let bundle = match recv_frame(&mut s).map_err(|e| Fail(10, format!("TRANSPORT {e}")))? {
        Frame::Bundle(b) => b,
        other => {
            return Err(Fail(
                10,
                format!("TRANSPORT expected a bundle, got {other:?}"),
            ))
        }
    };
    let mut refuse = |code: &str, detail: String| -> Fail {
        let msg = format!("{code} {detail}");
        let _ = send_frame(&mut s, &Frame::Refusal(msg.clone()));
        Fail(11, format!("REFUSED {msg}"))
    };
    let a = match admit_bundle(&bundle, &submitter, now()) {
        Ok(a) => a,
        Err(r) => {
            return Err(refuse(
                r.name(),
                format!("bundle_sha256={}", to_hex(&sha(&bundle))),
            ))
        }
    };
    let dag = to_hex(&a.digest);
    // AN0-GUARD replay
    if !mark_seen(&state, &dag)? {
        return Err(refuse(
            "AN0_REPLAY",
            format!("dag_id={dag} already admitted"),
        ));
    }
    eprintln!(
        "aienet0-serve: admitted dag_id={dag} matmul_u32 m={} k={} n={} seed={}",
        a.job.m, a.job.k, a.job.n, a.job.seed
    );
    let t0 = Instant::now();
    let mut out = matmul_u32_digest(&a.job);
    let ms = t0.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32;
    if misbehave.as_deref() == Some("wrong-output") {
        out[0] ^= 1;
    }
    let exe = std::env::current_exe()
        .and_then(fs::read)
        .map_err(|e| Fail(15, format!("cannot hash own executable: {e}")))?;
    let mut receipt = executor_receipt(&a, out, ms, sha(&exe), sha(POLICY.as_bytes()), &exec);
    if misbehave.as_deref() == Some("tamper-receipt") {
        receipt[144] ^= 1; // first byte of the MJR1 output_digest
    }
    send_frame(&mut s, &Frame::Receipt(receipt.to_vec()))
        .map_err(|e| Fail(10, format!("TRANSPORT {e}")))?;
    println!(
        "RECEIPT {dag} {} output={} executor={} time_ms={ms}",
        to_hex(&sha(&receipt)),
        to_hex(&out),
        to_hex(&public_key(&exec))
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = if args.first().map(String::as_str) == Some("keys") {
        need(&args, "--keys")
            .and_then(|d| keys(&PathBuf::from(d)))
            .map(|(t, e)| {
                println!("volunteer.ed25519 {}", to_hex(&t.pubkey_bytes()));
                println!("executor.p256 {}", to_hex(&public_key(&e)));
            })
    } else {
        serve(&args)
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(code, msg)) => {
            eprintln!("aienet0-serve: {msg}");
            println!("{msg}");
            ExitCode::from(code)
        }
    }
}
