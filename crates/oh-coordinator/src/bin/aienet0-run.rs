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
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
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

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Synchronize a unique temporary file, then link without replacing any
/// existing directory entry (including dangling symlinks).
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Fail> {
    let io = |e: std::io::Error| Fail(15, format!("{}: {e}", path.display()));
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".an0-output-{}-{}", std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(io)?;
    let result = (|| {
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
        // AN0-GUARD output-no-replace
        fs::hard_link(&tmp, path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Fail(15, format!("REFUSED AN0_OUTPUT_EXISTS {}", path.display()))
            } else {
                io(e)
            }
        })?;
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)
    })();
    fs::remove_file(&tmp).map_err(io)?;
    result
}

/// Run the pinned Omega recompute on the payload; returns its digest.
fn recompute(bin: &Path, want_sha: &str, payload: &[u8]) -> Result<[u8; 32], Fail> {
    recompute_with_timeout(bin, want_sha, payload, Duration::from_secs(30))
}

fn recompute_with_timeout(
    bin: &Path, want_sha: &str, payload: &[u8], timeout: Duration,
) -> Result<[u8; 32], Fail> {
    let got_sha = to_hex(&sha(&read_bytes(bin)?));
    // AN0-GUARD recompute-pin
    if got_sha != want_sha.trim() {
        return Err(Fail(
            13,
            format!("REFUSED AN0_RECOMPUTE_UNPINNED {got_sha}"),
        ));
    }
    let failed = |detail| Fail(13, format!("REFUSED AN0_RECOMPUTE_FAILED {detail}"));
    // Nonblocking parent endpoints keep stdin, stdout and exit under one
    // deadline. No pipe reader/writer thread can outlive a refused child.
    let (mut input, child_input) = UnixStream::pair()
        .map_err(|e| failed(format!("stdin: {e}")))?;
    let (mut output, child_output) = UnixStream::pair()
        .map_err(|e| failed(format!("stdout: {e}")))?;
    input.set_nonblocking(true).map_err(|e| failed(format!("stdin: {e}")))?;
    output.set_nonblocking(true).map_err(|e| failed(format!("stdout: {e}")))?;
    let deadline = Instant::now() + timeout;
    let mut child = Command::new(bin)
        .stdin(Stdio::from(OwnedFd::from(child_input)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| failed(format!("spawn: {e}")))?;
    let mut stdin_error = None;
    let result = (|| {
        let mut sent = 0;
        let mut input_closed = false;
        let mut bytes = [0; 66]; // one hex digest, optionally CRLF
        let mut used = 0;
        let mut eof = false;
        let mut status = None;
        loop {
            // AN0-GUARD recompute-deadline
            if Instant::now() >= deadline {
                return Err(failed("timeout".into()));
            }
            if sent < payload.len() && !input_closed {
                match input.write(&payload[sent..]) {
                    Ok(0) => stdin_error = Some(std::io::ErrorKind::WriteZero.into()),
                    Ok(n) => sent += n,
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock |
                        std::io::ErrorKind::Interrupted) => {}
                    Err(e) => stdin_error = Some(e),
                }
            }
            if (sent == payload.len() || stdin_error.is_some()) && !input_closed {
                if let Err(e) = input.shutdown(std::net::Shutdown::Write) {
                    stdin_error.get_or_insert(e);
                }
                input_closed = true;
            }
            if !eof {
                let mut chunk = [0; 67];
                match output.read(&mut chunk) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if n > bytes.len() - used {
                            return Err(failed("stdout: excess output".into()));
                        }
                        bytes[used..used + n].copy_from_slice(&chunk[..n]);
                        used += n;
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock |
                        std::io::ErrorKind::Interrupted) => {}
                    Err(e) => return Err(failed(format!("stdout: {e}"))),
                }
            }
            if status.is_none() {
                status = child.try_wait().map_err(|e| failed(format!("wait: {e}")))?;
            }
            if let Some(status) = status {
                if eof && input_closed {
                    if !status.success() {
                        return Err(failed(format!("exit={status}")));
                    }
                    let out = std::str::from_utf8(&bytes[..used])
                        .map_err(|e| failed(format!("stdout: {e}")))?;
                    let digest = from_hex::<32>(out)
                        .ok_or_else(|| failed("bad output".into()))?;
                    // Classify the child's output/exit before a write failure:
                    // an early-exiting child can close stdin before we write.
                    // A valid digest must never hide an input delivery error.
                    // AN0-GUARD recompute-stdin
                    if let Some(e) = stdin_error.take() {
                        return Err(failed(format!("stdin: {e}")));
                    }
                    return Ok(digest);
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    if let Err(mut err) = result {
        if let Some(e) = stdin_error {
            err.1.push_str(&format!("; stdin: {e}"));
        }
        // Signal only this owned, unreaped child, never a process group or
        // a PID discovered elsewhere. Reap it on every refusal path.
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(e) = child.kill() {
                    err.1.push_str(&format!("; child kill: {e}"));
                }
            }
            Err(e) => {
                err.1.push_str(&format!("; child status: {e}"));
                if let Err(e) = child.kill() {
                    err.1.push_str(&format!("; child kill: {e}"));
                }
            }
        }
        if let Err(e) = child.wait() {
            err.1.push_str(&format!("; child reap: {e}"));
        }
        return Err(err);
    }
    result
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
    // A retry may finish a prior requester interrupted between these files.
    // Existing artifacts are reusable only when byte-identical.
    for (path, bytes) in [
        (&mjr1_path, receipt.as_slice()),
        (&out_dir.join(format!("{dag}.mjv")), mjv.as_slice()),
    ] {
        match fs::read(path) {
            Ok(existing) if existing == bytes => {}
            Ok(_) => return Err(Fail(15, format!("REFUSED AN0_OUTPUT_EXISTS {} differs", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_new(path, bytes)?,
            Err(e) => return Err(Fail(15, format!("{}: {e}", path.display()))),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier, Mutex};

    // Keep executable fixture writes separate from other test spawns: a
    // pre-exec child can retain a writable descriptor and cause ETXTBUSY.
    static RECOMPUTE_FIXTURES: Mutex<()> = Mutex::new(());
    // Only mutual exclusion is shared, not mutable fixture state. Preserve
    // the first failed assertion without cascading poisoned-lock failures.

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("an0-output-{}-{}", std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn recompute_script(body: &str) -> (PathBuf, PathBuf, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let bin = dir.join("recompute");
        fs::write(&bin, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = to_hex(&sha(&fs::read(&bin).unwrap()));
        (dir, bin, digest)
    }

    #[test]
    fn recompute_deadline_covers_output_and_exit() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for body in ["exec sleep 2", "exec 1>&-; exec sleep 2",
            "printf '%064d\\n' 0; exec sleep 2"] {
            let (dir, bin, pin) = recompute_script(body);
            let started = Instant::now();
            let err = recompute_with_timeout(&bin, &pin, b"payload", Duration::from_millis(100))
                .expect_err("AN0_SEMANTIC recompute-deadline");
            assert!(started.elapsed() < Duration::from_secs(1), "AN0_SEMANTIC recompute-deadline");
            assert!(err.1.contains("timeout"), "unexpected recompute refusal: {err:?}");
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn recompute_deadline_covers_blocked_stdin() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let (dir, bin, pin) = recompute_script("exec sleep 2");
        let err = recompute_with_timeout(&bin, &pin, &[0; 1024 * 1024], Duration::from_millis(100))
            .expect_err("AN0_SEMANTIC recompute-deadline");
        assert!(err.1.contains("timeout"), "AN0_SEMANTIC recompute-deadline: {err:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recompute_refuses_excess_output_and_child_failure() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for (body, reason) in [
            ("printf '%067d' 0", "stdout: excess output"),
            ("cat >/dev/null; exit 7", "exit="),
            ("cat >/dev/null; printf 'bad\\n'", "bad output"),
        ] {
            let (dir, bin, pin) = recompute_script(body);
            let err = recompute_with_timeout(&bin, &pin, b"payload", Duration::from_secs(2))
                .expect_err("invalid recompute must refuse");
            assert!(err.1.contains(reason), "{err:?}");
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn recompute_classifies_child_failure_after_broken_stdin() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        for (body, reason, reads_to_exit) in [
            ("printf '%067d' 0", "stdout: excess output", false),
            ("exit 7", "exit=", true),
            ("printf 'bad\\n'", "bad output", true),
            ("printf '\\377\\n'", "stdout:", true),
        ] {
            let (dir, bin, pin) = recompute_script(&format!(
                "exec 0<&-; sleep 0.05; {body}"));
            let err = recompute_with_timeout(&bin, &pin, &[0; 1024 * 1024], Duration::from_secs(2))
                .expect_err("child failure must refuse");
            assert!(err.1.contains(reason), "{err:?}");
            // Excess output can refuse immediately, before a stdin error is
            // observed. Other cases drain to exit and retain that error.
            if reads_to_exit {
                assert!(err.1.contains("; stdin:"), "input failure must remain explicit: {err:?}");
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recompute_timeout_reaps_only_its_child() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let (dir, bin, _) = recompute_script("");
        let pidfile = dir.join("child.pid");
        fs::write(&bin, format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 2\n",
            pidfile.display())).unwrap();
        let pin = to_hex(&sha(&fs::read(&bin).unwrap()));
        let mut unrelated = Command::new("sleep").arg("2").spawn().unwrap();
        let result = recompute_with_timeout(&bin, &pin, b"", Duration::from_millis(100));
        let unrelated_running = unrelated.try_wait().unwrap().is_none();
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        let pid = fs::read_to_string(&pidfile).unwrap();
        assert!(result.unwrap_err().1.contains("timeout"));
        assert!(!Path::new("/proc").join(pid.trim()).exists(), "recompute child was not reaped");
        assert!(unrelated_running, "recompute affected an unrelated child");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recompute_refuses_stdin_io_error() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let digest = "00".repeat(32);
        let (dir, bin, pin) = recompute_script(&format!("exec 0<&-; printf '{digest}\\n'"));
        let err = recompute_with_timeout(&bin, &pin, &[0; 1024 * 1024], Duration::from_secs(2))
            .expect_err("AN0_SEMANTIC recompute-stdin");
        assert!(err.1.contains("stdin:"), "unexpected recompute refusal: {err:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recompute_refuses_stdout_io_error() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let (dir, bin, pin) = recompute_script("cat >/dev/null; printf '\\377\\n'");
        let err = recompute_with_timeout(&bin, &pin, b"payload", Duration::from_secs(2))
            .expect_err("AN0_SEMANTIC recompute-stdout");
        assert!(err.1.contains("stdout:"), "AN0_SEMANTIC recompute-stdout: {err:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recompute_accepts_pinned_digest_and_refuses_wrong_pin() {
        let _fixture = RECOMPUTE_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let (dir, bin, pin) = recompute_script("cat >/dev/null; printf '%064d\\n' 0");
        assert_eq!(recompute(&bin, &pin, b"payload").unwrap(), [0; 32]);
        let err = recompute(&bin, &"f".repeat(64), b"payload")
            .expect_err("AN0_SEMANTIC recompute-pin");
        assert!(err.1.contains("AN0_RECOMPUTE_UNPINNED"),
            "unexpected recompute refusal: {err:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_new_refuses_dangling_destination() {
        let dir = scratch();
        let path = dir.join("result");
        symlink(dir.join("missing"), &path).unwrap();
        assert!(write_new(&path, b"must not replace").is_err(),
            "AN0_SEMANTIC output-no-replace");
        assert!(path.symlink_metadata().unwrap().file_type().is_symlink(), "AN0_SEMANTIC output-no-replace: destination replaced");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_new_has_one_concurrent_winner() {
        let dir = scratch();
        let path = dir.join("result");
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [b'a', b'b'].into_iter().map(|byte| {
            let (path, barrier) = (path.clone(), barrier.clone());
            thread::spawn(move || {
                barrier.wait();
                write_new(&path, &[byte; 4096]).is_ok()
            })
        }).collect();
        let winners = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!(winners, 1);
        let bytes = fs::read(&path).unwrap();
        assert!(bytes == [b'a'; 4096] || bytes == [b'b'; 4096]);
        assert!(write_new(&path, b"overwrite").is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_new_does_not_touch_preexisting_temp() {
        let dir = scratch();
        let path = dir.join("result");
        let old_tmp = path.with_extension("tmp");
        fs::write(&old_tmp, b"another writer").unwrap();
        write_new(&path, b"complete result").unwrap();
        assert_eq!(fs::read(old_tmp).unwrap(), b"another writer");
        assert_eq!(fs::read(path).unwrap(), b"complete result");
        fs::remove_dir_all(dir).unwrap();
    }
}
