//! `aienet0-serve`: the Aienet-0 P0 worker. Connects to one coordinator,
//! receives one submitter-signed MJB1 bundle over the pinned encrypted
//! transport, and admits only the allowlisted `matmul_u32` job within bounds.
//! Admission and the signed result are durable states. Interrupted jobs resume
//! on redelivery; completed jobs refuse replay unless `--retry` requests the
//! exact stored receipt. It runs in the foreground and never listens.
//!
//! Usage: aienet0-serve keys --keys DIR
//!        aienet0-serve --connect HOST:PORT --keys DIR --pins DIR --state DIR
//!                      [--connect-timeout SECS]
//!                      [--retry]
//!                      [--misbehave wrong-output|tamper-receipt]
//!
//! `--keys DIR`: `transport.seed` (Ed25519 seed, hex) and `executor.p256`
//! (P-256 scalar, hex): test identities, not a wallet.
//! `--pins DIR`: `coordinator.ed25519` (32-byte hex) and `submitter.p256`
//! (33-byte compressed hex), exchanged out of band; no trust on first use.
//! `--state DIR`: strict, atomically published `seen` state and a permanent
//! `lock`. The exclusive lock spans admission, compute and durable completion.
//! Old bare-digest `seen` entries remain replay-only, with no invented result.
//! `--misbehave` exists only for the negative controls: `wrong-output`
//! signs an output digest with one bit flipped (a dishonest worker);
//! `tamper-receipt` flips one bit of the output digest after signing (a
//! receipt altered in flight).
//!
//! Exit: 0 receipt sent, 2 usage or key files, 10 transport, 11 refused
//! the bundle (refusal sent to the coordinator), 15 local i/o.

use aien_microjob::aienet0::{
    admit_bundle, check_receipt, executor_receipt, from_hex, matmul_u32_digest, public_key,
    signing_key_from_hex, to_hex,
};
use aien_microjob::{decode_receipt, RECEIPT_LEN};
use oh_core::carrier::{recv_frame, send_frame, Frame};
use oh_core::{keypair_from_seed_hex, volunteer_handshake, CoordinatorPin};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The admission policy in force; its SHA-256 is the receipt's `policy_hash`.
const POLICY: &str = "AIENET0-WORKER-POLICY-V2 allow=matmul_u32 mjb1.op=MATMUL payload.kind=1 \
dims=1..=256 caps>=job verifier=RECOMPUTE replay=refuse retry=cached-or-resume submitter=pinned coordinator=pinned";

#[derive(Debug)]
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

const STATE_HEADER: &str = "AIENET0-STATE-V1\n";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

// Keep the bounded receipt inline with its job rather than allocate it separately.
#[allow(clippy::large_enum_variant)]
enum JobState {
    Legacy,
    Job {
        bundle: [u8; 32],
        executor: [u8; 33],
        receipt: Option<[u8; RECEIPT_LEN]>,
    },
}

// This short-lived decision carries the same fixed-size receipt by value.
#[allow(clippy::large_enum_variant)]
enum Admission {
    Execute,
    Cached([u8; RECEIPT_LEN]),
    Replay,
}

struct State {
    // The lock inode is permanent, unlike the atomically replaced snapshot.
    _lock: File,
    dir: PathBuf,
    jobs: BTreeMap<String, JobState>,
}

fn state_io(e: std::io::Error) -> Fail {
    Fail(15, format!("state: {e}"))
}

fn malformed() -> Fail {
    Fail(15, "state: malformed seen file".into())
}

fn hex<const N: usize>(s: &str) -> Result<[u8; N], Fail> {
    let bytes = from_hex::<N>(s).ok_or_else(malformed)?;
    if to_hex(&bytes) != s {
        return Err(malformed());
    }
    Ok(bytes)
}

impl State {
    fn open(dir: &Path) -> Result<Self, Fail> {
        fs::create_dir_all(dir).map_err(state_io)?;
        let lock = OpenOptions::new()
            .create(true).truncate(false).read(true).write(true)
            .open(dir.join("lock")).map_err(state_io)?;
        // AN0-GUARD state-lock
        lock.try_lock().map_err(|e| Fail(15, format!("state lock: {e}")))?;
        File::open(dir).and_then(|d| d.sync_all()).map_err(state_io)?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent).and_then(|d| d.sync_all()).map_err(state_io)?;
        }
        let mut jobs = BTreeMap::new();
        let text = match fs::read_to_string(dir.join("seen")) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            // AN0-GUARD state-read
            Err(e) => return Err(state_io(e)),
        };
        if let Some(text) = text {
            // AN0-GUARD state-parse
            if text.is_empty() || !text.ends_with('\n') {
                return Err(malformed());
            }
            if let Some(records) = text.strip_prefix(STATE_HEADER) {
                for line in records.split_terminator('\n') {
                    let mut fields = line.split(' ');
                    let fields = [fields.next(), fields.next(), fields.next(),
                        fields.next(), fields.next(), fields.next()];
                    let (dag, record) = match fields {
                        [Some("legacy"), Some(dag), None, None, None, None] => (dag, JobState::Legacy),
                        [Some(status @ ("admitted" | "done")), Some(dag), Some(bundle), Some(executor), last, None] => {
                            let receipt = match (status, last) {
                                ("admitted", None) => None,
                                ("done", Some(bytes)) => {
                                    let bytes = hex::<RECEIPT_LEN>(bytes)?;
                                    let r = decode_receipt(&bytes).map_err(|_| malformed())?;
                                    if to_hex(&r.dag_digest) != dag || to_hex(&r.signer_key) != executor {
                                        return Err(malformed());
                                    }
                                    Some(bytes)
                                }
                                _ => return Err(malformed()),
                            };
                            (dag, JobState::Job { bundle: hex(bundle)?, executor: hex(executor)?, receipt })
                        }
                        _ => return Err(malformed()),
                    };
                    hex::<32>(dag)?;
                    if jobs.insert(dag.to_string(), record).is_some() {
                        return Err(malformed());
                    }
                }
            } else {
                for dag in text.split_terminator('\n') {
                    hex::<32>(dag)?;
                    if jobs.insert(dag.to_string(), JobState::Legacy).is_some() {
                        return Err(malformed());
                    }
                }
            }
        }
        Ok(Self { _lock: lock, dir: dir.to_path_buf(), jobs })
    }

    fn commit(&self) -> Result<(), Fail> {
        let tmp = self.dir.join(format!(".seen-{}-{}", std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(state_io)?;
        let result = (|| {
            file.write_all(STATE_HEADER.as_bytes()).map_err(state_io)?;
            for (dag, record) in &self.jobs {
                match record {
                    JobState::Legacy => writeln!(file, "legacy {dag}"),
                    JobState::Job { bundle, executor, receipt } => match receipt {
                        None => writeln!(file, "admitted {dag} {} {}", to_hex(bundle), to_hex(executor)),
                        Some(receipt) => writeln!(file, "done {dag} {} {} {}", to_hex(bundle), to_hex(executor), to_hex(receipt)),
                    },
                }.map_err(state_io)?;
            }
            file.sync_all().map_err(state_io)?;
            fs::rename(&tmp, self.dir.join("seen")).map_err(state_io)?;
            File::open(&self.dir).and_then(|d| d.sync_all()).map_err(state_io)
        })();
        // A killed writer may leave an unreferenced temp, never authoritative state.
        let _ = fs::remove_file(tmp);
        result
    }

    fn begin(&mut self, dag: &str, bundle: [u8; 32], executor: [u8; 33], retry: bool) -> Result<Admission, Fail> {
        if let Some(record) = self.jobs.get(dag) {
            return match record {
                JobState::Legacy => Ok(Admission::Replay),
                JobState::Job { bundle: original, executor: owner, receipt } => {
                    if *original != bundle || *owner != executor {
                        return Err(Fail(15, "state: admission identity mismatch".into()));
                    }
                    if let Some(receipt) = receipt {
                        // AN0-GUARD replay
                        if !retry {
                            return Ok(Admission::Replay);
                        }
                        // AN0-GUARD cached-result
                        return Ok(Admission::Cached(*receipt));
                    }
                    // AN0-GUARD recovery
                    Ok(Admission::Execute)
                }
            };
        }
        self.jobs.insert(dag.to_string(), JobState::Job { bundle, executor, receipt: None });
        self.commit()?;
        Ok(Admission::Execute)
    }

    fn run(&mut self, dag: &str, bundle: [u8; 32], executor: [u8; 33], retry: bool,
        compute: impl FnOnce() -> Result<[u8; RECEIPT_LEN], Fail>) -> Result<Option<[u8; RECEIPT_LEN]>, Fail> {
        match self.begin(dag, bundle, executor, retry)? {
            Admission::Replay => Ok(None),
            Admission::Cached(receipt) => Ok(Some(receipt)),
            Admission::Execute => {
                #[cfg(test)]
                fault_pause("admitted");
                let receipt = compute()?;
                #[cfg(test)]
                fault_pause("computed");
                self.jobs.insert(dag.to_string(), JobState::Job { bundle, executor, receipt: Some(receipt) });
                self.commit()?;
                #[cfg(test)]
                fault_pause("done");
                Ok(Some(receipt))
            }
        }
    }
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
    let retry = args.iter().any(|arg| arg == "--retry");
    let mut durable = State::open(&state)?;
    let receipt = durable.run(&dag, sha(&bundle), public_key(&exec), retry, || {
        eprintln!(
            "aienet0-serve: executing dag_id={dag} matmul_u32 m={} k={} n={} seed={}",
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
        Ok(executor_receipt(&a, out, ms, sha(&exe), sha(POLICY.as_bytes()), &exec))
    })?;
    let mut receipt = match receipt {
        Some(receipt) => receipt,
        None => return Err(refuse("AN0_REPLAY", format!("dag_id={dag} already completed or legacy admission"))),
    };
    // Recheck persisted results against this exact, currently valid request.
    let result = check_receipt(&a.document, &receipt, public_key(&exec), now())
        .map_err(|e| Fail(15, format!("state: invalid stored receipt: {}", e.name())))?;
    drop(durable);
    if misbehave.as_deref() == Some("tamper-receipt") {
        receipt[144] ^= 1; // first byte of the MJR1 output_digest
    }
    send_frame(&mut s, &Frame::Receipt(receipt.to_vec()))
        .map_err(|e| Fail(10, format!("TRANSPORT {e}")))?;
    println!(
        "RECEIPT {dag} {} output={} executor={} time_ms={}",
        to_hex(&sha(&receipt)),
        to_hex(&result.output_digest),
        to_hex(&public_key(&exec)),
        result.used_time_ms
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

// Only test binaries contain crash injection; production has no such switch.
#[cfg(test)]
fn fault_pause(phase: &str) {
    if std::env::var("AN0_TEST_PAUSE").ok().as_deref() == Some(phase) {
        fs::write(std::env::var_os("AN0_TEST_READY").expect("test ready path"), phase).unwrap();
        loop {
            thread::park_timeout(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use aien_microjob::aienet0::{build_document, seal_bundle, Admitted, MatmulU32};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "an0-state-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn seen_rejects_corruption() {
        let dag = "a".repeat(64);
        let invalid = [
            b"not-a-digest\n".to_vec(), b"\xff\n".to_vec(), Vec::new(),
            dag.as_bytes().to_vec(), format!("{dag}\n{dag}\n").into_bytes(),
            format!("{STATE_HEADER}unknown {dag}\n").into_bytes(),
            format!("{STATE_HEADER}legacy {}\n", "A".repeat(64)).into_bytes(),
            format!("{dag}\r\n").into_bytes(),
            format!("{STATE_HEADER}done {dag} {dag} {} {}\n", "a".repeat(66), "a".repeat(808)).into_bytes(),
        ];
        for bytes in invalid {
            let dir = scratch();
            fs::write(dir.join("seen"), &bytes).unwrap();
            assert!(State::open(&dir).is_err(), "AN0_SEMANTIC state-parse: corrupt state admitted a job");
            assert_eq!(fs::read(dir.join("seen")).unwrap(), bytes);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn seen_rejects_write_only_file() {
        let dir = scratch();
        let path = dir.join("seen");
        fs::write(&path, format!("{}\n", "b".repeat(64))).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
        let result = State::open(&dir);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(result.is_err(), "AN0_SEMANTIC state-read: unreadable state admitted a job");
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{}\n", "b".repeat(64)));
        fs::remove_dir_all(dir).unwrap();
    }

    fn fixture() -> (Admitted, [u8; 32], p256::ecdsa::SigningKey) {
        let key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let job = MatmulU32 { m: 2, k: 2, n: 2, seed: 7 };
        let payload = job.encode();
        // Fixed fixture time is independent of child-process scheduling.
        let doc = build_document(&payload, aien_microjob::compute_op::MATMUL, [9; 16], &public_key(&key), 1_800_000_000);
        let bundle = seal_bundle(&doc, &payload, &key);
        (admit_bundle(&bundle, &public_key(&key), 1_800_000_000).unwrap(), sha(&bundle), key)
    }

    fn result(a: &Admitted, exec: &p256::ecdsa::SigningKey) -> [u8; RECEIPT_LEN] {
        executor_receipt(a, matmul_u32_digest(&a.job), 1, [2; 32], sha(POLICY.as_bytes()), exec)
    }

    #[test]
    fn legacy_replay_is_refused() {
        let dir = scratch();
        let (a, bundle, exec) = fixture();
        let dag = to_hex(&a.digest);
        fs::write(dir.join("seen"), format!("{dag}\n")).unwrap();
        let mut state = State::open(&dir).unwrap();
        for retry in [false, true] {
            assert!(state.run(&dag, bundle, public_key(&exec), retry, || panic!("legacy replay executed")).unwrap().is_none());
        }
        drop(state);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_duplicate_executes_once() {
        for retry in [false, true] {
            let dir = scratch();
            let start = Arc::new(Barrier::new(2));
            let executions = Arc::new(AtomicU64::new(0));
            let handles: Vec<_> = (0..2).map(|_| {
                let (dir, start, executions) = (dir.clone(), start.clone(), executions.clone());
                thread::spawn(move || {
                    let (a, bundle, exec) = fixture();
                    start.wait();
                    match State::open(&dir) {
                        Ok(mut state) => {
                            state.run(&to_hex(&a.digest), bundle, public_key(&exec), retry, || {
                                executions.fetch_add(1, Ordering::SeqCst);
                                thread::sleep(Duration::from_millis(100));
                                Ok(result(&a, &exec))
                            }).unwrap()
                        }
                        Err(Fail(_, msg)) if msg.starts_with("state lock:") => None,
                        Err(e) => panic!("{e:?}"),
                    }
                })
            }).collect();
            let receipts: Vec<_> = handles.into_iter().filter_map(|h| h.join().unwrap()).collect();
            assert!(!receipts.is_empty());
            assert_eq!(executions.load(Ordering::SeqCst), 1);
            for receipt in receipts {
                let (a, _, exec) = fixture();
                check_receipt(&a.document, &receipt, public_key(&exec), 1_800_000_000).unwrap();
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    #[ignore = "entry point for crash_recovery child process"]
    fn crash_worker() {
        let dir = PathBuf::from(std::env::var_os("AN0_TEST_DIR").unwrap());
        let (a, bundle, exec) = fixture();
        let mut state = State::open(&dir).unwrap();
        let receipt = state.run(&to_hex(&a.digest), bundle, public_key(&exec), true, || {
            Ok(witnessed_result(&dir, &a, &exec))
        }).unwrap().expect("recovery refused");
        check_receipt(&a.document, &receipt, public_key(&exec), 1_800_000_000).unwrap();
    }

    fn witnessed_result(dir: &Path, a: &Admitted, exec: &p256::ecdsa::SigningKey) -> [u8; RECEIPT_LEN] {
        let mut witness = OpenOptions::new().create(true).append(true).open(dir.join("executions")).unwrap();
        witness.write_all(b"execute\n").unwrap();
        witness.sync_all().unwrap();
        result(a, exec)
    }

    #[test]
    fn crash_recovery() {
        for phase in ["admitted", "computed", "done"] {
            let dir = scratch();
            let ready = dir.join("ready");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "tests::crash_worker", "--nocapture"])
                .env("AN0_TEST_DIR", &dir).env("AN0_TEST_PAUSE", phase).env("AN0_TEST_READY", &ready)
                .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.exists() {
                assert!(child.try_wait().unwrap().is_none(), "worker exited before {phase}");
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("worker did not reach {phase}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            let excluded = State::open(&dir).is_err();
            child.kill().unwrap();
            assert_eq!(child.wait().unwrap().signal(), Some(9));
            assert!(excluded, "AN0_SEMANTIC state-lock: live worker did not exclude another process");
            let (a, bundle, exec) = fixture();
            let dag = to_hex(&a.digest);
            let mut state = State::open(&dir).unwrap();
            let receipt = state.run(&dag, bundle, public_key(&exec), false, || Ok(witnessed_result(&dir, &a, &exec))).unwrap();
            let expected = result(&a, &exec);
            if phase == "done" {
                assert!(receipt.is_none(), "AN0_SEMANTIC replay: default completed replay must refuse");
            } else {
                assert_eq!(receipt, Some(expected), "AN0_SEMANTIC recovery: interrupted admission must resume");
            }
            drop(state);
            let mut state = State::open(&dir).unwrap();
            let cached = state.run(&dag, bundle, public_key(&exec), true, ||
                panic!("AN0_SEMANTIC cached-result: completed job re-executed")).unwrap();
            assert_eq!(cached, Some(expected));
            check_receipt(&a.document, &cached.unwrap(), public_key(&exec), 1_800_000_000).unwrap();
            assert!(state.run(&dag, [0; 32], public_key(&exec), true, || panic!("mismatched bundle executed")).is_err());
            assert!(state.run(&dag, bundle, [0; 33], true, || panic!("wrong executor executed")).is_err());
            let executions = fs::read_to_string(dir.join("executions")).unwrap();
            assert_eq!(executions.lines().count(), if phase == "computed" { 2 } else { 1 });
            drop(state);
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
