//! The volunteer sends back only its signed update, and refuses work it
//! cannot trust.

use beacon_core::Keypair;
use oh_core::{
    recv, send, BaseModel, Learner, Receipt, TinyByteModel, Update, WireError, WorkUnit,
};
use oh_volunteer::{run_once, Settings, VolunteerError};
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Random lowercase letters and spaces: every 16-byte run is unique, so a
/// match in outbound bytes can only mean the shard leaked.
fn random_text(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            b"abcdefghijklmnopqrstuvwxyz "[((state >> 33) % 27) as usize]
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn base_model(dim: usize) -> BaseModel {
    BaseModel {
        dim: dim as u32,
        params: TinyByteModel::new(dim, 1).params(),
    }
}

fn settings() -> Settings {
    Settings {
        seed: 3,
        keep_fraction: 0.05,
        coordinator_key: None,
    }
}

/// Passes reads through and keeps a copy of every byte written.
struct Recorder<S> {
    inner: S,
    sent: Vec<u8>,
}

impl<S: Read> Read for Recorder<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Recorder<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sent.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A scripted coordinator: fixed bytes to read, and a sink for writes.
fn scripted(base: &BaseModel, unit: &WorkUnit) -> Recorder<Cursor<Vec<u8>>> {
    let mut input = Vec::new();
    send(&mut input, base).unwrap();
    send(&mut input, unit).unwrap();
    Recorder {
        inner: Cursor::new(input),
        sent: Vec::new(),
    }
}

#[test]
fn test_update_frame_carries_no_shard_bytes() {
    let coordinator = Keypair::generate();
    let base = base_model(8);
    let shard = random_text(4096, 7);
    let unit = WorkUnit::new_signed(&coordinator, [1; 16], 1, base.digest(), shard.clone(), 40);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_unit = unit.clone();
    let server_base = base.clone();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        send(&mut s, &server_base).unwrap();
        send(&mut s, &server_unit).unwrap();
        let update: Update = recv(&mut s).unwrap();
        update.verify_for(&server_unit).unwrap();
        send(
            &mut s,
            &Receipt::new_signed(&coordinator, &update, 1.5, true),
        )
        .unwrap();
    });

    let mut stream = Recorder {
        inner: TcpStream::connect(addr).unwrap(),
        sent: Vec::new(),
    };
    let outcome = run_once(&mut stream, &Keypair::generate(), &settings()).unwrap();
    server.join().unwrap();
    assert!(outcome.accepted);
    assert_eq!(outcome.turings, 1.5);

    // Exactly one frame went out, and it is exactly the encoded update.
    let sent = stream.sent;
    let len = u32::from_be_bytes(sent[..4].try_into().unwrap()) as usize;
    assert_eq!(sent.len(), 4 + len, "one frame and nothing else");
    let update: Update = recv(&mut Cursor::new(&sent)).unwrap();
    let mut reencoded = Vec::new();
    send(&mut reencoded, &update).unwrap();
    assert_eq!(
        reencoded, sent,
        "the frame holds the update and no extra bytes"
    );

    // The update keeps at most 5% of the parameters, as 8-bit values.
    let kept_cap = (TinyByteModel::num_params(8) as f64 * 0.05).round() as usize;
    assert!(update.delta.indices.len() <= kept_cap);

    // No 16-byte run of the shard appears in anything sent.
    for window in shard.windows(16) {
        assert!(!contains(&sent, window), "shard bytes left the volunteer");
    }
    // Negative control: the same check does find shard runs in the work unit.
    let mut unit_bytes = Vec::new();
    send(&mut unit_bytes, &unit).unwrap();
    assert!(contains(&unit_bytes, &shard[100..116]));
}

#[test]
fn test_work_unit_with_bad_signature_is_refused() {
    let coordinator = Keypair::generate();
    let base = base_model(8);
    let mut unit = WorkUnit::new_signed(
        &coordinator,
        [1; 16],
        1,
        base.digest(),
        random_text(512, 1),
        10,
    );
    unit.shard[0] ^= 1;

    let mut stream = scripted(&base, &unit);
    let err = run_once(&mut stream, &Keypair::generate(), &settings()).unwrap_err();
    assert!(
        matches!(err, VolunteerError::Wire(WireError::BadSignature)),
        "got {err:?}"
    );
    assert!(stream.sent.is_empty(), "nothing is sent for a refused unit");
}

#[test]
fn test_work_unit_from_unexpected_coordinator_is_refused() {
    let base = base_model(8);
    let unit = WorkUnit::new_signed(
        &Keypair::generate(),
        [1; 16],
        1,
        base.digest(),
        random_text(512, 1),
        10,
    );
    let mut pinned = settings();
    pinned.coordinator_key = Some(Keypair::generate().pubkey_bytes());

    let mut stream = scripted(&base, &unit);
    let err = run_once(&mut stream, &Keypair::generate(), &pinned).unwrap_err();
    assert!(
        matches!(err, VolunteerError::Wire(WireError::WrongSigner)),
        "got {err:?}"
    );
    assert!(stream.sent.is_empty());
}

#[test]
fn test_base_model_that_does_not_match_the_unit_is_refused() {
    let base = base_model(8);
    let unit = WorkUnit::new_signed(
        &Keypair::generate(),
        [1; 16],
        1,
        [0; 32],
        random_text(512, 1),
        10,
    );

    let mut stream = scripted(&base, &unit);
    let err = run_once(&mut stream, &Keypair::generate(), &settings()).unwrap_err();
    assert!(matches!(err, VolunteerError::BadBase(_)), "got {err:?}");
    assert!(stream.sent.is_empty());
}
