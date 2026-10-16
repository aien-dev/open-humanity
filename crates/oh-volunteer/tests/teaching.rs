//! Teaching mode sends only firewalled teaching text, and refuses text the
//! Personal Data Firewall flags.

use beacon_core::Keypair;
use oh_core::{
    read_frame, recv_submission, send, BaseModel, Learner, Receipt, Submission, Teacher,
    TeacherError, TinyByteModel, WorkUnit, TEACHING_FRAME_TAG,
};
use oh_volunteer::{teach_once, teach_summary_line, Settings, VolunteerError, MAX_HINT_BYTES};
use std::cell::RefCell;
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Random lowercase words separated by single spaces: every 16-byte run is
/// unique, so a match in outbound bytes can only mean the shard leaked.
fn random_words(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = 2 + (state >> 60) as usize % 7;
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push(b'a' + ((state >> 33) % 26) as u8);
        }
        out.push(b' ');
    }
    out.truncate(n);
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A teacher that returns a fixed reply, optionally after the hint, and
/// remembers every prompt it was given.
struct FakeTeacher {
    reply: String,
    echo_hint: bool,
    prompts: RefCell<Vec<String>>,
}

impl FakeTeacher {
    fn new(reply: &str) -> Self {
        Self {
            reply: reply.into(),
            echo_hint: false,
            prompts: RefCell::new(Vec::new()),
        }
    }
}

impl Teacher for FakeTeacher {
    fn generate(&self, prompt: &str, _max_tokens: u32) -> Result<String, TeacherError> {
        self.prompts.borrow_mut().push(prompt.to_string());
        if self.echo_hint {
            let hint = prompt.rsplit("\n\n").next().unwrap();
            // The period is not in the shard alphabet, so no 16-byte window
            // can run from the hint into the reply by coincidence.
            return Ok(format!("{hint}. {}", self.reply));
        }
        Ok(self.reply.clone())
    }
}

struct FailingTeacher;

impl Teacher for FailingTeacher {
    fn generate(&self, _: &str, _: u32) -> Result<String, TeacherError> {
        Err(TeacherError::BadResponse("server is down".into()))
    }
}

fn settings() -> Settings {
    Settings {
        seed: 3,
        keep_fraction: 0.05,
        coordinator_key: None,
    }
}

fn base_model() -> BaseModel {
    BaseModel {
        dim: 8,
        params: TinyByteModel::new(8, 1).params(),
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

/// Runs one teaching exchange against a coordinator thread that answers
/// with a receipt worth 2.5 Turings. Returns everything the volunteer sent.
fn teach_over_loopback(
    teacher: &FakeTeacher,
    shard: &[u8],
) -> (Vec<u8>, oh_volunteer::Outcome, WorkUnit) {
    let coordinator = Keypair::generate();
    let base = base_model();
    let unit = WorkUnit::new_signed(&coordinator, [1; 16], 1, base.digest(), shard.to_vec(), 40);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_unit = unit.clone();
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        send(&mut s, &base).unwrap();
        send(&mut s, &server_unit).unwrap();
        let Submission::Teaching(batch) = recv_submission(&mut s).unwrap() else {
            panic!("expected a teaching batch");
        };
        batch.verify_for(&server_unit).unwrap();
        send(
            &mut s,
            &Receipt::for_teaching(&coordinator, &batch, 2.5, true),
        )
        .unwrap();
    });
    let mut stream = Recorder {
        inner: TcpStream::connect(addr).unwrap(),
        sent: Vec::new(),
    };
    let outcome = teach_once(&mut stream, &Keypair::generate(), &settings(), teacher, 64).unwrap();
    server.join().unwrap();
    (stream.sent, outcome, unit)
}

#[test]
fn test_teaching_frame_carries_only_firewalled_text() {
    let shard = random_words(4096, 7);
    let teacher = FakeTeacher::new(
        "Open models learn from clear text. Notes live in /home/alice/notes/today.txt on her machine.",
    );
    let (sent, outcome, unit) = teach_over_loopback(&teacher, &shard);
    assert!(outcome.accepted);
    assert_eq!(outcome.turings, 2.5);
    assert_eq!(
        teach_summary_line(1, &outcome),
        "Batch 1: accepted, earned 2.500 Turings"
    );

    // Exactly one frame went out: the tagged teaching batch, nothing else.
    let mut cursor = Cursor::new(&sent);
    let frame = read_frame(&mut cursor).unwrap();
    assert_eq!(cursor.position() as usize, sent.len(), "one frame only");
    assert!(frame.starts_with(TEACHING_FRAME_TAG));
    let Submission::Teaching(batch) = recv_submission(&mut Cursor::new(&sent)).unwrap() else {
        panic!("not a teaching batch");
    };
    let mut reencoded = Vec::new();
    oh_core::send_teaching(&mut reencoded, &batch).unwrap();
    assert_eq!(
        reencoded, sent,
        "the frame holds the batch and no extra bytes"
    );

    // The text is the firewalled reply: the home path is redacted.
    assert_eq!(
        batch.text,
        b"Open models learn from clear text. Notes live in ~/notes/today.txt on her machine."
    );
    assert!(!contains(&sent, b"/home/alice/"));

    // The prompt held one short printable hint from the shard.
    let prompts = teacher.prompts.borrow();
    assert_eq!(prompts.len(), 1);
    let hint = prompts[0].rsplit("\n\n").next().unwrap();
    assert!(
        !hint.is_empty() && hint.len() <= MAX_HINT_BYTES,
        "hint {hint:?}"
    );
    assert!(hint.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
    assert!(
        contains(&shard, hint.as_bytes()),
        "hint is not from the shard"
    );

    // No 16-byte run of the shard appears in anything sent.
    for window in shard.windows(16) {
        assert!(!contains(&sent, window), "shard bytes left the volunteer");
    }
    // Negative control: the same check finds shard runs in the work unit.
    let mut unit_bytes = Vec::new();
    send(&mut unit_bytes, &unit).unwrap();
    assert!(contains(&unit_bytes, &shard[100..116]));
}

#[test]
fn test_echoing_teacher_leaks_no_shard_bytes_beyond_the_hint() {
    let shard = random_words(4096, 8);
    let mut teacher = FakeTeacher::new("And that is how the passage ends.");
    teacher.echo_hint = true;
    let (sent, _, _) = teach_over_loopback(&teacher, &shard);
    let prompts = teacher.prompts.borrow();
    let hint = prompts[0].rsplit("\n\n").next().unwrap().as_bytes();

    let mut leaked = 0;
    for window in shard.windows(16) {
        if contains(&sent, window) {
            leaked += 1;
            assert!(
                contains(hint, window),
                "shard bytes outside the hint were sent"
            );
        }
    }
    // Negative control: the echoed hint itself is found.
    assert!(leaked > 0);
}

#[test]
fn test_text_with_a_fake_api_key_is_refused() {
    let coordinator = Keypair::generate();
    let base = base_model();
    let unit = WorkUnit::new_signed(
        &coordinator,
        [1; 16],
        1,
        base.digest(),
        random_words(512, 1),
        10,
    );
    // The firewall's own test patterns, split so this file holds no key.
    let keys = [
        format!("AWS_ACCESS_KEY_ID={}{}", "AKIA", "IOSFODNN7EXAMPLE"),
        format!("token {}{}", "ghp_", "123456789012345678901234567890123456"),
        format!(
            "key {}{}",
            "sk-ant-", "123456789012345678901234567890123456"
        ),
    ];
    for key in &keys {
        let teacher = FakeTeacher::new(&format!("Here is a passage. {key} The end."));
        let mut input = Vec::new();
        send(&mut input, &base).unwrap();
        send(&mut input, &unit).unwrap();
        let mut stream = Recorder {
            inner: Cursor::new(input),
            sent: Vec::new(),
        };
        let err =
            teach_once(&mut stream, &Keypair::generate(), &settings(), &teacher, 64).unwrap_err();
        assert!(matches!(err, VolunteerError::Firewall(_)), "got {err:?}");
        assert!(stream.sent.is_empty(), "something was sent for {key}");
        // The refusal message names the kind, never the secret itself.
        let secret = key.split([' ', '=']).next_back().unwrap();
        assert!(!err.to_string().contains(secret), "{err}");
    }
}

#[test]
fn test_teacher_failure_or_empty_text_sends_nothing() {
    let base = base_model();
    let unit = WorkUnit::new_signed(
        &Keypair::generate(),
        [1; 16],
        1,
        base.digest(),
        random_words(512, 2),
        10,
    );
    let scripted = || {
        let mut input = Vec::new();
        send(&mut input, &base).unwrap();
        send(&mut input, &unit).unwrap();
        Recorder {
            inner: Cursor::new(input),
            sent: Vec::new(),
        }
    };

    let mut stream = scripted();
    let err = teach_once(
        &mut stream,
        &Keypair::generate(),
        &settings(),
        &FailingTeacher,
        64,
    )
    .unwrap_err();
    assert!(matches!(err, VolunteerError::Teacher(_)), "got {err:?}");
    assert!(stream.sent.is_empty());

    let mut stream = scripted();
    let blank = FakeTeacher::new("   \n ");
    let err = teach_once(&mut stream, &Keypair::generate(), &settings(), &blank, 64).unwrap_err();
    assert!(matches!(err, VolunteerError::EmptyTeaching), "got {err:?}");
    assert!(stream.sent.is_empty());
}

#[test]
fn test_unsigned_work_unit_is_refused_before_the_teacher_runs() {
    let base = base_model();
    let mut unit = WorkUnit::new_signed(
        &Keypair::generate(),
        [1; 16],
        1,
        base.digest(),
        random_words(512, 3),
        10,
    );
    unit.shard[0] ^= 1;
    let mut input = Vec::new();
    send(&mut input, &base).unwrap();
    send(&mut input, &unit).unwrap();
    let mut stream = Recorder {
        inner: Cursor::new(input),
        sent: Vec::new(),
    };
    let teacher = FakeTeacher::new("never asked");
    assert!(teach_once(&mut stream, &Keypair::generate(), &settings(), &teacher, 64).is_err());
    assert!(teacher.prompts.borrow().is_empty());
    assert!(stream.sent.is_empty());
}
