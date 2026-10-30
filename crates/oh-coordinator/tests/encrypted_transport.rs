//! An eavesdropper on the loopback link between `Coordinator::serve` and
//! its volunteers sees no shard bytes and no teaching text.
//!
//! A relay sits between the volunteers and the coordinator and records every
//! byte in both directions for one full round: one training volunteer and
//! one teaching volunteer, both pinned to the coordinator key.

use beacon_core::Keypair;
use oh_coordinator::{Coordinator, RoundReport, Settings};
use oh_core::{
    send, send_teaching, volunteer_handshake, CoordinatorPin, Ledger, Teacher, TeacherError,
    TeachingBatch, WorkUnit,
};
use oh_volunteer::{run_once, teach_once};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

const LICENSE: &[u8] = include_bytes!("../../../LICENSE");
const WINDOW: usize = 16;
const TEACHING_TEXT: &str = "Every person who receives a copy of the program may read the \
source, change it to suit their own needs, and pass the improved version on to their friends.";

struct FakeTeacher;

impl Teacher for FakeTeacher {
    fn generate(&self, _prompt: &str, _max_tokens: u32) -> Result<String, TeacherError> {
        Ok(TEACHING_TEXT.into())
    }
}

/// Copies bytes from `from` to `to`, appending each chunk to `log`.
fn pump(mut from: TcpStream, mut to: TcpStream, log: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                log.lock().unwrap().extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// Relays `connections` connections from a new listener to `target` and
/// records everything. Returns the relay address and the capture.
fn eavesdropper(target: SocketAddr, connections: usize) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let capture: Arc<Mutex<Vec<u8>>> = Arc::default();
    let log = capture.clone();
    thread::spawn(move || {
        for _ in 0..connections {
            let (client, _) = listener.accept().unwrap();
            let server = TcpStream::connect(target).unwrap();
            let (c2, s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
            let (l1, l2) = (log.clone(), log.clone());
            thread::spawn(move || pump(client, server, l1));
            thread::spawn(move || pump(s2, c2, l2));
        }
    });
    (addr, capture)
}

/// True when any `WINDOW`-byte run of `needle` appears in `haystack`.
fn leaks(haystack: &[u8], needle: &[u8]) -> bool {
    let seen: HashSet<&[u8]> = haystack.windows(WINDOW).collect();
    needle.windows(WINDOW).any(|w| seen.contains(w))
}

#[test]
fn test_eavesdropper_sees_no_shard_or_teaching_bytes() {
    let dir = std::env::temp_dir().join(format!("oh-encrypted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let settings = Settings {
        volunteers_per_round: 2,
        steps: 20,
        heldout_fraction: 0.1,
        seed: 3,
        dim: 8,
        outer_lr: 1.0,
    };
    let mut coordinator = Coordinator::new(
        LICENSE,
        &settings,
        Ledger::open(&dir.join("ledger.jsonl")).unwrap(),
    )
    .unwrap();
    let key = coordinator.pubkey();
    let train = LICENSE[..coordinator.train_len()].to_vec();
    let trainer_node = Keypair::generate();
    let node = Keypair::generate();
    coordinator.approve_volunteers([trainer_node.pubkey_bytes(), node.pubkey_bytes()]);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (relay, capture) = eavesdropper(listener.local_addr().unwrap(), 2);
    let server = thread::spawn(move || {
        let mut reports: Vec<RoundReport> = Vec::new();
        coordinator
            .serve(&listener, 1, |r| reports.push(r.clone()))
            .unwrap();
        reports
    });

    let vol_settings = move |seed| oh_volunteer::Settings {
        seed,
        keep_fraction: 0.05,
        coordinator_key: Some(key),
    };
    let trainer = thread::spawn(move || {
        let node = trainer_node;
        let stream = TcpStream::connect(relay).unwrap();
        let mut s = volunteer_handshake(stream, &node, CoordinatorPin::Key(key)).unwrap();
        run_once(&mut s, &node, &vol_settings(1)).unwrap()
    });
    let stream = TcpStream::connect(relay).unwrap();
    let mut s = volunteer_handshake(stream, &node, CoordinatorPin::Key(key)).unwrap();
    let taught = teach_once(&mut s, &node, &vol_settings(2), &FakeTeacher, 64).unwrap();
    drop(s);
    trainer.join().unwrap();
    let reports = server.join().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].taught, 1, "{:?}", reports[0]);
    assert!(taught.accepted);

    let captured = capture.lock().unwrap().clone();
    // Both shards (about 15 KB each) and the base model crossed the link.
    assert!(
        captured.len() > train.len(),
        "capture {} bytes",
        captured.len()
    );

    // Negative control: the same check finds both in plain frames,
    // so a clean result below means the bytes really were hidden.
    let unit = WorkUnit::new_signed(&node, [0; 16], 1, [0; 32], train[..64].to_vec(), 1);
    let batch = TeachingBatch::new_signed(&node, &unit, TEACHING_TEXT.as_bytes().to_vec());
    let mut plain = Vec::new();
    send(&mut plain, &unit).unwrap();
    send_teaching(&mut plain, &batch).unwrap();
    assert!(leaks(&plain, TEACHING_TEXT.as_bytes()));
    assert!(leaks(&plain, &train[..64]));

    assert!(!leaks(&captured, &train), "shard bytes visible on the wire");
    assert!(
        !leaks(&captured, TEACHING_TEXT.as_bytes()),
        "teaching text visible on the wire"
    );
    assert!(!captured.windows(8).any(|w| w == b"OHTEACH1"));
}
