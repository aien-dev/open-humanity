//! Coordinator and volunteers over real loopback TCP, in one process.

use beacon_core::Keypair;
use oh_coordinator::{Coordinator, RoundReport, Settings, Verdict};
use oh_core::{read_frame, Ledger, Update, WorkUnit};
use oh_volunteer::{run_once, Outcome};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// Words drawn at random from a small list: enough structure for the model
/// to learn, deterministic for a given seed.
fn corpus(n: usize, seed: u64) -> Vec<u8> {
    let words = [
        "the",
        "open",
        "model",
        "learns",
        "from",
        "signed",
        "updates",
        "and",
        "never",
        "sees",
        "personal",
        "data",
        "volunteers",
        "train",
        "at",
        "home",
        "while",
        "coordinator",
        "scores",
        "every",
        "change",
        "in",
        "turings",
        "of",
        "held",
        "out",
        "text",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(words[((state >> 33) % words.len() as u64) as usize].as_bytes());
        out.push(if (state >> 20).is_multiple_of(9) {
            b'.'
        } else {
            b' '
        });
    }
    out.truncate(n);
    out
}

fn settings() -> Settings {
    Settings {
        volunteers_per_round: 2,
        steps: 150,
        heldout_fraction: 0.1,
        seed: 5,
        dim: 16,
    }
}

fn volunteer_settings(seed: u64) -> oh_volunteer::Settings {
    oh_volunteer::Settings {
        seed,
        keep_fraction: 0.05,
        coordinator_key: None,
    }
}

fn fresh_ledger(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oh-coordinator-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("ledger.jsonl")
}

/// Starts one volunteer thread that takes `rounds` work units from `addr`.
fn spawn_volunteer(
    addr: SocketAddr,
    rounds: u32,
    seed: u64,
) -> thread::JoinHandle<([u8; 32], Vec<Outcome>)> {
    thread::spawn(move || {
        let keypair = Keypair::generate();
        let settings = volunteer_settings(seed);
        let outcomes = (0..rounds)
            .map(|_| {
                let mut stream = TcpStream::connect(addr).unwrap();
                run_once(&mut stream, &keypair, &settings).unwrap()
            })
            .collect();
        (keypair.pubkey_bytes(), outcomes)
    })
}

#[test]
fn test_two_volunteers_two_rounds_over_loopback() {
    let ledger_path = fresh_ledger("two-rounds");
    let mut coordinator = Coordinator::new(
        &corpus(6000, 1),
        &settings(),
        Ledger::open(&ledger_path).unwrap(),
    )
    .unwrap();
    let key = coordinator.pubkey();
    let start = coordinator.heldout_bpb();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut reports: Vec<RoundReport> = Vec::new();
        coordinator
            .serve(&listener, 2, |r| reports.push(r.clone()))
            .unwrap();
        reports
    });
    let volunteers: Vec<_> = (0..2).map(|i| spawn_volunteer(addr, 2, 10 + i)).collect();
    let results: Vec<_> = volunteers.into_iter().map(|v| v.join().unwrap()).collect();
    let reports = server.join().unwrap();

    // Held-out bits never rise from round to round.
    assert_eq!(reports.len(), 2);
    let mut previous = start;
    for r in &reports {
        eprintln!("{}", r.line());
        assert!(r.heldout_bpb <= previous, "held-out bits rose: {r:?}");
        previous = r.heldout_bpb;
    }
    assert!(
        reports.iter().any(|r| r.applied),
        "no round improved the model"
    );

    // Every receipt is signed by the coordinator, and every accepted
    // update was credited in the ledger.
    let ledger = Ledger::open(&ledger_path).unwrap();
    let mut accepted = 0;
    for (node, outcomes) in &results {
        let mut earned = 0.0;
        for o in outcomes {
            o.receipt.verify_from(&key).unwrap();
            if o.accepted {
                accepted += 1;
                earned += o.turings;
            }
        }
        assert!((ledger.total(node) - earned).abs() < 1e-9);
    }
    assert!(accepted > 0, "no update was accepted");
}

/// Passes reads through and copies every written byte into a shared buffer.
struct Recorder {
    inner: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl Read for Recorder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn test_no_heldout_bytes_in_any_frame_sent() {
    const RUN: usize = 16;
    let text = corpus(6000, 2);
    let mut coordinator = Coordinator::new(
        &text,
        &settings(),
        Ledger::open(&fresh_ledger("sealed")).unwrap(),
    )
    .unwrap();
    let heldout = coordinator.heldout().to_vec();
    let train = &text[..text.len() - heldout.len()];

    // Held-out runs that do not also occur in the training part; any of
    // these in a frame could only have come from the held-out tail.
    let train_runs: HashSet<&[u8]> = train.windows(RUN).collect();
    let sealed: HashSet<&[u8]> = heldout
        .windows(RUN)
        .filter(|w| !train_runs.contains(w))
        .collect();
    assert!(
        sealed.len() > 100,
        "test corpus too repetitive: {}",
        sealed.len()
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Vec<Arc<Mutex<Vec<u8>>>> = (0..4).map(|_| Arc::default()).collect();
    let buffers = captured.clone();
    let server = thread::spawn(move || {
        for round in 0..2 {
            let mut conns: Vec<Recorder> = (0..2)
                .map(|i| Recorder {
                    inner: listener.accept().unwrap().0,
                    sent: buffers[round * 2 + i].clone(),
                })
                .collect();
            coordinator.run_round(&mut conns).unwrap();
        }
    });
    let volunteers: Vec<_> = (0..2).map(|i| spawn_volunteer(addr, 2, 20 + i)).collect();
    for v in volunteers {
        v.join().unwrap();
    }
    server.join().unwrap();

    let mut units = 0;
    for buffer in &captured {
        let bytes = buffer.lock().unwrap().clone();
        let mut cursor = Cursor::new(&bytes);
        let mut frames = Vec::new();
        while (cursor.position() as usize) < bytes.len() {
            frames.push(read_frame(&mut cursor).unwrap());
        }
        // Base model, work unit, receipt.
        assert_eq!(frames.len(), 3, "unexpected frame count");
        for frame in &frames {
            assert!(
                !frame.windows(RUN).any(|w| sealed.contains(w)),
                "a held-out run was sent to a volunteer"
            );
        }
        let unit: WorkUnit =
            oh_core::recv(&mut Cursor::new(&bytes[4 + frames[0].len()..])).unwrap();
        assert!(unit.shard.len() > 100);
        assert!(
            train
                .windows(unit.shard.len())
                .any(|w| w == unit.shard.as_slice()),
            "shard is not a slice of the training part"
        );
        units += 1;
    }
    assert_eq!(units, 4);

    // Negative control: the same check does flag a frame holding held-out bytes.
    assert!(heldout.windows(RUN).any(|w| sealed.contains(w)));
}

#[test]
fn test_replayed_update_is_rejected() {
    let ledger_path = fresh_ledger("replay");
    let mut coordinator = Coordinator::new(
        &corpus(6000, 3),
        &settings(),
        Ledger::open(&ledger_path).unwrap(),
    )
    .unwrap();
    let base = coordinator.begin_round();
    let (unit0, unit1) = (coordinator.work_unit(0), coordinator.work_unit(1));
    let volunteer = Keypair::generate();
    let update = oh_volunteer::train(&base, &unit0, &volunteer, &volunteer_settings(1)).unwrap();

    let first = coordinator.judge(&unit0, &update).unwrap();
    assert!(matches!(first, Verdict::Accepted { .. }), "got {first:?}");

    let again = coordinator.judge(&unit0, &update).unwrap();
    assert!(matches!(again, Verdict::Rejected { .. }), "got {again:?}");

    // The same delta signed again for another work unit is still a replay.
    let moved = Update::new_signed(&volunteer, &unit1, update.delta.clone());
    let moved_verdict = coordinator.judge(&unit1, &moved).unwrap();
    assert!(
        matches!(moved_verdict, Verdict::Rejected { .. }),
        "got {moved_verdict:?}"
    );

    // An update presented against the wrong work unit is dropped.
    let wrong = coordinator.judge(&unit1, &update).unwrap();
    assert!(matches!(wrong, Verdict::Dropped(_)), "got {wrong:?}");

    // One credit line and one rejected line per rejection; dropped updates
    // get no receipt and no line.
    let text = std::fs::read_to_string(&ledger_path).unwrap();
    assert_eq!(text.matches("\"kind\":\"credit\"").count(), 1);
    assert_eq!(text.matches("\"kind\":\"rejected\"").count(), 2);
    assert_eq!(text.matches("replay of an earlier update").count(), 2);
}

#[test]
fn test_round_is_discarded_when_the_average_does_not_help() {
    let mut coordinator = Coordinator::new(
        &corpus(6000, 4),
        &settings(),
        Ledger::open(&fresh_ledger("discard")).unwrap(),
    )
    .unwrap();
    let base = coordinator.begin_round();
    let before = coordinator.heldout_bpb();

    // A large, fixed push on every parameter wrecks the model.
    let harmful = vec![vec![5.0f32; base.params.len()]];
    let report = coordinator.finish_round(&harmful);
    assert!(report.aggregate_turings <= 0.0, "got {report:?}");
    assert!(!report.applied, "a harmful average was applied");
    assert_eq!(report.heldout_bpb, before, "the model changed");

    // A zero average scores exactly zero, which also discards the round.
    coordinator.begin_round();
    let zero = vec![vec![0.0f32; base.params.len()]];
    let report = coordinator.finish_round(&zero);
    assert_eq!(report.aggregate_turings, 0.0);
    assert!(!report.applied);
    assert_eq!(report.heldout_bpb, before);
}
