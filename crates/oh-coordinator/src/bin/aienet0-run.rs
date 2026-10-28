//! `aienet0-run`: the Aienet-0 P0 requester and verifier. Builds one MJB1
//! `matmul_u32` job, signs it as the submitter, waits for the one pinned
//! volunteer on the encrypted transport, sends the bundle, and verifies the
//! MJR1 receipt that comes back: the aien-microjob ledger with only the
//! pinned executor key trusted, then an independent recompute by the Omega
//! program (pinned by SHA-256), then the verdict commitment. Only then it
//! countersigns, writes `<out>/<dag_id>.mjr1` and `<dag_id>.mjv`, prints
//! `VERIFIED <dag_id> <mjr1_sha256> <mjr1_path>` and exits 0.
//!
//! Usage: aienet0-run keys --keys DIR
//!        aienet0-run bundle --keys DIR --out FILE
//!                    [--m M --k K --n N --seed S] [--op matmul|compile]
//!                    [--payload-kind K]
//!        aienet0-run run --listen ADDR --keys DIR --pins DIR --out DIR
//!                    --recompute BIN --recompute-sha256 HEX
//!                    [--m M --k K --n N --seed S] [--op matmul|compile]
//!                    [--payload-kind K] [--resend BUNDLE] [--accept-timeout SECS]
//!        aienet0-run check --bundle F --mjr1 F --mjv F --keys DIR --pins DIR
//!
//! `bundle` only builds and signs the job, writes it to a new FILE and prints
//! `BUNDLE <dag_id> <path>`, so escrow can be reserved on the dag_id before
//! anything is sent; `run --resend FILE` then sends exactly those bytes.
//! Replay is judged by the worker's persistent seen set, so a bundle that was
//! never sent is admitted on its first `--resend`.
//!
//! `--keys DIR`: `transport.seed` (Ed25519 seed), `submitter.p256`,
//! `verifier.p256` (P-256 scalars), all hex test identities, not a wallet.
//! `--pins DIR`: `volunteer.ed25519` (32-byte hex) and `executor.p256`
//! (33-byte compressed hex). `--op compile` and `--payload-kind` exist for
//! the negative controls (not allowlisted).
//!
//! Exit: 0 VERIFIED, 2 usage or key files, 10 transport, 11 the worker
//! refused, 12 the receipt validator refused, 13 recompute refused or
//! mismatched, 14 verdict commitment mismatch, 15 local i/o or output
//! already present.

use aien_microjob::aienet0::{
    build_document, check_countersign, check_receipt, countersign, from_hex, public_key,
    seal_bundle, signing_key_from_hex, split_bundle, to_hex, An0Refusal, MatmulU32, DOCUMENT_TTL,
};
use aien_microjob::{compute_op, dag_digest, decode};
use oh_core::carrier::{recv_frame, send_frame, Frame};
use oh_core::{coordinator_handshake_pinned, keypair_from_seed_hex};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fail(u8, String);

type P256 = p256::ecdsa::SigningKey;

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

fn num<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> Result<T, Fail> {
    match value(args, flag) {
        None => Ok(default),
        Some(s) => s
            .parse()
            .map_err(|_| Fail(2, format!("{flag} {s} is not a number"))),
    }
}

fn read_text(p: &Path) -> Result<String, Fail> {
    fs::read_to_string(p).map_err(|e| Fail(2, format!("cannot read {}: {e}", p.display())))
}

fn read_bytes(p: &Path) -> Result<Vec<u8>, Fail> {
    fs::read(p).map_err(|e| Fail(2, format!("cannot read {}: {e}", p.display())))
}

fn p256_key(p: &Path) -> Result<P256, Fail> {
    signing_key_from_hex(&read_text(p)?)
        .ok_or_else(|| Fail(2, format!("{} is not a P-256 scalar in hex", p.display())))
}

fn pin<const N: usize>(p: &Path) -> Result<[u8; N], Fail> {
    from_hex::<N>(&read_text(p)?)
        .ok_or_else(|| Fail(2, format!("{} is not {N}-byte hex", p.display())))
}

fn refused(code: u8, r: An0Refusal) -> Fail {
    Fail(code, format!("REFUSED {}", r.name()))
}

/// Write `bytes` to `path` with no overwrite: temp file, fsync, rename,
/// fsync of the directory.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Fail> {
    let io = |e: std::io::Error| Fail(15, format!("{}: {e}", path.display()));
    if path.exists() {
        return Err(Fail(
            15,
            format!("REFUSED AN0_OUTPUT_EXISTS {}", path.display()),
        ));
    }
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp).map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    }
    Ok(())
}

/// Run the pinned Omega recompute on the payload; returns its digest.
fn recompute(bin: &Path, want_sha: &str, payload: &[u8]) -> Result<[u8; 32], Fail> {
    let got_sha = to_hex(&sha(&read_bytes(bin)?));
    // AN0-GUARD recompute-pin
    if got_sha != want_sha.trim() {
        return Err(Fail(
            13,
            format!("REFUSED AN0_RECOMPUTE_UNPINNED {got_sha}"),
        ));
    }
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Fail(13, format!("REFUSED AN0_RECOMPUTE_FAILED spawn: {e}")))?;
    child.stdin.take().expect("piped").write_all(payload).ok();
    let mut out = String::new();
    child
        .stdout
        .take()
        .expect("piped")
        .read_to_string(&mut out)
        .ok();
    let status = child
        .wait()
        .map_err(|e| Fail(13, format!("REFUSED AN0_RECOMPUTE_FAILED {e}")))?;
    if !status.success() {
        return Err(Fail(
            13,
            format!("REFUSED AN0_RECOMPUTE_FAILED exit={status}"),
        ));
    }
    from_hex::<32>(&out).ok_or_else(|| Fail(13, "REFUSED AN0_RECOMPUTE_FAILED bad output".into()))
}

fn accept(listen: &str, timeout: Duration) -> Result<std::net::TcpStream, Fail> {
    let l = TcpListener::bind(listen)
        .map_err(|e| Fail(10, format!("cannot listen on {listen}: {e}")))?;
    l.set_nonblocking(true)
        .map_err(|e| Fail(10, e.to_string()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match l.accept() {
            Ok((s, peer)) => {
                eprintln!("aienet0-run: connection from {peer}");
                s.set_nonblocking(false)
                    .map_err(|e| Fail(10, e.to_string()))?;
                s.set_read_timeout(Some(Duration::from_secs(300))).ok();
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(Fail(10, format!("no volunteer connected: {e}"))),
        }
    }
}

fn run(args: &[String]) -> Result<(), Fail> {
    let keys = PathBuf::from(need(args, "--keys")?);
    let pins = PathBuf::from(need(args, "--pins")?);
    let transport = keypair_from_seed_hex(read_text(&keys.join("transport.seed"))?.as_bytes())
        .map_err(|e| Fail(2, format!("transport.seed: {e}")))?;
    let submitter = p256_key(&keys.join("submitter.p256"))?;
    let verifier = p256_key(&keys.join("verifier.p256"))?;
    let volunteer = pin::<32>(&pins.join("volunteer.ed25519"))?;
    let executor = pin::<33>(&pins.join("executor.p256"))?;
    let out_dir = PathBuf::from(need(args, "--out")?);
    let bin = PathBuf::from(need(args, "--recompute")?);
    let bin_sha = need(args, "--recompute-sha256")?;
    fs::create_dir_all(&out_dir).map_err(|e| Fail(15, format!("{}: {e}", out_dir.display())))?;

    let bundle = match value(args, "--resend") {
        Some(f) => read_bytes(Path::new(&f))?,
        None => make_bundle(args, &submitter)?,
    };
    let (_, _, payload, doc) = split_bundle(&bundle).map_err(|r| refused(2, r))?;
    let (payload, doc) = (payload.to_vec(), doc.to_vec());
    let dag = to_hex(&dag_digest(&doc));
    let bundle_path = out_dir.join(format!("{dag}.an0b"));
    if !bundle_path.exists() {
        write_new(&bundle_path, &bundle)?;
    } else if read_bytes(&bundle_path)? != bundle {
        return Err(Fail(
            15,
            format!(
                "REFUSED AN0_OUTPUT_EXISTS {} differs",
                bundle_path.display()
            ),
        ));
    }
    eprintln!(
        "aienet0-run: dag_id={dag} payload={} bundle={} coordinator={}",
        to_hex(&payload),
        bundle_path.display(),
        to_hex(&transport.pubkey_bytes())
    );

    let listen = need(args, "--listen")?;
    let stream = accept(
        &listen,
        Duration::from_secs(num(args, "--accept-timeout", 120)?),
    )?;
    let mut s = coordinator_handshake_pinned(stream, &transport, volunteer)
        .map_err(|e| Fail(10, format!("REFUSED TRANSPORT {e}")))?;
    send_frame(&mut s, &Frame::Bundle(bundle)).map_err(|e| Fail(10, format!("TRANSPORT {e}")))?;
    let receipt = match recv_frame(&mut s).map_err(|e| Fail(10, format!("TRANSPORT {e}")))? {
        Frame::Receipt(r) => r,
        Frame::Refusal(why) => return Err(Fail(11, format!("REFUSED WORKER {why}"))),
        Frame::Bundle(_) => return Err(Fail(10, "TRANSPORT volunteer sent a bundle".into())),
    };
    eprintln!("aienet0-run: receipt sha256={}", to_hex(&sha(&receipt)));

    let r = check_receipt(&doc, &receipt, executor, now()).map_err(|r| refused(12, r))?;
    let mine = recompute(&bin, &bin_sha, &payload)?;
    eprintln!(
        "aienet0-run: executor output={} omega recompute={}",
        to_hex(&r.output_digest),
        to_hex(&mine)
    );
    let mjv = countersign(&receipt, mine, &verifier).map_err(|r| {
        let code = if r == An0Refusal::VerdictMismatch {
            14
        } else {
            13
        };
        refused(code, r)
    })?;
    let mjr1_path = out_dir.join(format!("{dag}.mjr1"));
    write_new(&mjr1_path, &receipt)?;
    write_new(&out_dir.join(format!("{dag}.mjv")), &mjv)?;
    println!(
        "VERIFIED {dag} {} {}",
        to_hex(&sha(&receipt)),
        mjr1_path.display()
    );
    Ok(())
}

/// Build and sign one job from the command-line shape. A fresh nonce makes
/// every bundle, and so every dag_id, distinct.
fn make_bundle(args: &[String], submitter: &P256) -> Result<Vec<u8>, Fail> {
    let job = MatmulU32 {
        m: num(args, "--m", 64)?,
        k: num(args, "--k", 64)?,
        n: num(args, "--n", 64)?,
        seed: num(args, "--seed", 0xA1E7_0001)?,
    };
    let mut payload = job.encode().to_vec();
    payload[0] = num(args, "--payload-kind", payload[0])?;
    let op = match value(args, "--op").as_deref() {
        None | Some("matmul") => compute_op::MATMUL,
        Some("compile") => compute_op::COMPILE,
        Some(o) => return Err(Fail(2, format!("unknown --op {o}"))),
    };
    let mut nonce = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut nonce))
        .map_err(|e| Fail(15, format!("/dev/urandom: {e}")))?;
    let doc = build_document(&payload, op, nonce, &public_key(submitter), now());
    Ok(seal_bundle(&doc, &payload, submitter))
}

/// `bundle`: sign one job and store it without sending, for a reservation
/// keyed on its dag_id.
fn bundle(args: &[String]) -> Result<(), Fail> {
    let keys = PathBuf::from(need(args, "--keys")?);
    let submitter = p256_key(&keys.join("submitter.p256"))?;
    let path = PathBuf::from(need(args, "--out")?);
    let bundle = make_bundle(args, &submitter)?;
    let (_, _, _, doc) = split_bundle(&bundle).map_err(|r| refused(2, r))?;
    let dag = to_hex(&dag_digest(doc));
    write_new(&path, &bundle)?;
    println!("BUNDLE {dag} {}", path.display());
    Ok(())
}

/// Offline re-check of stored artifacts as of the document's issue time:
/// submitter signature, ledger with the pinned executor, countersignature
/// with this verifier key.
fn check(args: &[String]) -> Result<(), Fail> {
    let keys = PathBuf::from(need(args, "--keys")?);
    let pins = PathBuf::from(need(args, "--pins")?);
    let bundle = read_bytes(Path::new(&need(args, "--bundle")?))?;
    let receipt = read_bytes(Path::new(&need(args, "--mjr1")?))?;
    let mjv = read_bytes(Path::new(&need(args, "--mjv")?))?;
    let submitter = public_key(&p256_key(&keys.join("submitter.p256"))?);
    let verifier = public_key(&p256_key(&keys.join("verifier.p256"))?);
    let executor = pin::<33>(&pins.join("executor.p256"))?;
    let (_, _, _, doc) = split_bundle(&bundle).map_err(|r| refused(12, r))?;
    let issued = decode(doc)
        .map_err(|r| refused(12, r.into()))?
        .header
        .expires_at
        - DOCUMENT_TTL;
    aien_microjob::aienet0::admit_bundle(&bundle, &submitter, issued)
        .map_err(|r| refused(12, r))?;
    check_receipt(doc, &receipt, executor, issued).map_err(|r| refused(12, r))?;
    check_countersign(&mjv, &receipt, &verifier).map_err(|r| refused(14, r))?;
    println!(
        "CHECKED {} {}",
        to_hex(&dag_digest(doc)),
        to_hex(&sha(&receipt))
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("keys") => need(&args, "--keys").and_then(|d| {
            let d = PathBuf::from(d);
            let t = keypair_from_seed_hex(read_text(&d.join("transport.seed"))?.as_bytes())
                .map_err(|e| Fail(2, format!("transport.seed: {e}")))?;
            println!("coordinator.ed25519 {}", to_hex(&t.pubkey_bytes()));
            println!(
                "submitter.p256 {}",
                to_hex(&public_key(&p256_key(&d.join("submitter.p256"))?))
            );
            println!(
                "verifier.p256 {}",
                to_hex(&public_key(&p256_key(&d.join("verifier.p256"))?))
            );
            Ok(())
        }),
        Some("bundle") => bundle(&args),
        Some("run") => run(&args),
        Some("check") => check(&args),
        _ => Err(Fail(
            2,
            "usage: aienet0-run keys|run|check ... (see source header)".into(),
        )),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(code, msg)) => {
            eprintln!("aienet0-run: {msg}");
            println!("{msg}");
            ExitCode::from(code)
        }
    }
}
