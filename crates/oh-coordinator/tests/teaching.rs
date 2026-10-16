//! Teaching batches from an in-process fake teacher, scored in Turings by
//! the coordinator over real loopback TCP, alongside ordinary updates.

use beacon_core::Keypair;
use oh_coordinator::{Coordinator, RoundReport, Settings, TeachingVerdict};
use oh_core::{
    volunteer_handshake, CoordinatorPin, EncryptedStream, Ledger, Teacher, TeacherError,
    TeachingBatch,
};
use oh_volunteer::{run_once, teach_once};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

/// Words drawn at random from a small list: enough structure for the model
/// to learn, deterministic for a given seed. Same generator as loopback.rs.
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

/// Stands in for the local Qwen: answers every prompt with fixed text.
struct FakeTeacher(String);

impl Teacher for FakeTeacher {
    fn generate(&self, _prompt: &str, _max_tokens: u32) -> Result<String, TeacherError> {
        Ok(self.0.clone())
    }
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
    let dir = std::env::temp_dir().join(format!("oh-teaching-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("ledger.jsonl")
}

fn good_text(seed: u64) -> String {
    String::from_utf8(corpus(1500, seed)).unwrap()
}

/// Connects to a coordinator started with `serve` and opens the encrypted
/// transport, pinned to `key`.
fn secure(addr: SocketAddr, node: &Keypair, key: [u8; 32]) -> EncryptedStream<TcpStream> {
    volunteer_handshake(
        TcpStream::connect(addr).unwrap(),
        node,
        CoordinatorPin::Key(key),
    )
    .unwrap()
}

#[test]
fn test_teacher_and_trainer_share_a_round_over_loopback() {
    let ledger_path = fresh_ledger("shared-round");
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

    let trainer = thread::spawn(move || {
        let keypair = Keypair::generate();
        for _ in 0..2 {
            let mut stream = secure(addr, &keypair, key);
            run_once(&mut stream, &keypair, &volunteer_settings(11)).unwrap();
        }
    });
    let teacher_node = Keypair::generate();
    let mut outcomes = Vec::new();
    for round in 0..2u64 {
        let teacher = FakeTeacher(good_text(100 + round));
        let mut stream = secure(addr, &teacher_node, key);
        outcomes.push(
            teach_once(
                &mut stream,
                &teacher_node,
                &volunteer_settings(12),
                &teacher,
                256,
            )
            .unwrap(),
        );
    }
    trainer.join().unwrap();
    let reports = server.join().unwrap();

    let mut previous = start;
    for r in &reports {
        eprintln!("{}", r.line());
        assert_eq!(r.taught, 1, "one teaching batch accepted per round: {r:?}");
        assert!(r.heldout_bpb <= previous, "held-out bits rose: {r:?}");
        previous = r.heldout_bpb;
    }
    assert!(reports[0].taught_applied == 1, "{:?}", reports[0]);
    assert!(reports[0].line().ends_with("taught=1 taught_applied=1"));

    let mut earned = 0.0;
    for (i, o) in outcomes.iter().enumerate() {
        eprintln!("teaching batch {}: {:.3} Turings", i + 1, o.turings);
        o.receipt.verify_from(&key).unwrap();
        assert!(o.accepted && o.turings > 0.0);
        earned += o.turings;
    }
    let ledger = Ledger::open(&ledger_path).unwrap();
    assert!((ledger.total(&teacher_node.pubkey_bytes()) - earned).abs() < 1e-9);
}

#[test]
fn test_replayed_or_misplaced_teaching_is_refused() {
    let ledger_path = fresh_ledger("replay");
    let mut coordinator = Coordinator::new(
        &corpus(6000, 3),
        &settings(),
        Ledger::open(&ledger_path).unwrap(),
    )
    .unwrap();
    coordinator.begin_round();
    let unit = coordinator.work_unit(0);
    let node = Keypair::generate();
    let batch = TeachingBatch::new_signed(&node, &unit, good_text(7).into_bytes());

    let first = coordinator.judge_teaching(&unit, &batch).unwrap();
    assert!(
        matches!(first, TeachingVerdict::Accepted { .. }),
        "got {first:?}"
    );
    let again = coordinator.judge_teaching(&unit, &batch).unwrap();
    assert!(
        matches!(&again, TeachingVerdict::Rejected { reason, .. } if reason.contains("replay")),
        "got {again:?}"
    );
    // The same text under another key is still a replay.
    let copied = TeachingBatch::new_signed(&Keypair::generate(), &unit, batch.text.clone());
    let copied_verdict = coordinator.judge_teaching(&unit, &copied).unwrap();
    assert!(
        matches!(copied_verdict, TeachingVerdict::Rejected { .. }),
        "got {copied_verdict:?}"
    );

    // A batch for another round is dropped without a receipt.
    coordinator.begin_round();
    let next = coordinator.work_unit(0);
    let stale = TeachingBatch::new_signed(&node, &unit, good_text(8).into_bytes());
    let stale_verdict = coordinator.judge_teaching(&next, &stale).unwrap();
    assert!(
        matches!(stale_verdict, TeachingVerdict::Dropped(_)),
        "got {stale_verdict:?}"
    );

    let text = std::fs::read_to_string(&ledger_path).unwrap();
    assert_eq!(text.matches("\"kind\":\"credit\"").count(), 1);
    assert_eq!(text.matches("replay of earlier teaching text").count(), 2);
}

#[test]
fn test_teaching_is_kept_only_if_it_still_helps_after_the_aggregate() {
    let mut coordinator = Coordinator::new(
        &corpus(6000, 4),
        &settings(),
        Ledger::open(&fresh_ledger("keep")).unwrap(),
    )
    .unwrap();
    coordinator.begin_round();
    let before = coordinator.heldout_bpb();

    // One repeated byte teaches the model to expect only that byte.
    let harmful = vec![b'z'; 2000];
    let report = coordinator.finish_round_with_teaching(&[], &[harmful]);
    assert_eq!((report.taught, report.taught_applied), (1, 0), "{report:?}");
    assert_eq!(report.heldout_bpb, before, "harmful text changed the model");

    coordinator.begin_round();
    let report = coordinator.finish_round_with_teaching(&[], &[good_text(9).into_bytes()]);
    assert_eq!((report.taught, report.taught_applied), (1, 1), "{report:?}");
    assert!(report.heldout_bpb < before);
}
