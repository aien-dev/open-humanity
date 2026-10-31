//! The engine bearer token (SI DRA-56): the volunteer reads the SI wizard's
//! token file and sends `Authorization: Bearer` to an engine that enforces
//! it; without a file it sends none; a file others can read is refused.

mod common;

use common::*;
use oh_infer::bearer::load_bearer_token;
use oh_infer::engine::{Engine, EngineError, HttpEngine};
use oh_infer::protocol::{ChatMessage, Job, Role};
use std::io::BufReader;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TOKEN: &str = "5f0e9d8c7b6a59483726150f1e2d3c4b5a69788796a5b4c3d2e1f00112233445";
const WRONG: &str = "6a1fae9d8c7b6a59483726150f1e2d3c4b5a69788796a5b4c3d2e1f001122334";

/// `root/auth/bearer-token` with the wizard's modes (or `fmode`).
fn token_file(root: &Path, text: &str, fmode: u32) -> PathBuf {
    let dir = root.join("auth");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let f = dir.join("bearer-token");
    std::fs::write(&f, format!("{text}\n")).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(fmode)).unwrap();
    f
}

fn job() -> Job {
    Job {
        job_id: [1; 16],
        model_id: "fake-model-0001".into(),
        messages: vec![ChatMessage {
            role: Role::User,
            content: "hello".into(),
        }],
        max_tokens: 8,
        seed: 0,
    }
}

fn run(engine: &HttpEngine) -> Result<String, EngineError> {
    let mut text = String::new();
    engine
        .generate(&job(), &mut |t| {
            text.push_str(t);
            Ok(())
        })
        .map(|_| text)
}

#[test]
fn http_engine_sends_the_token_and_an_enforcing_engine_needs_it() {
    let model = model_dir("tok-http");
    let fake = fake_engine_requiring(honest_reply, Some(TOKEN.into()));

    let right = load_bearer_token(&token_file(&model.dir.join("r"), TOKEN, 0o600)).unwrap();
    let ok = run(&HttpEngine::new(&fake.addr).with_bearer(right)).unwrap();
    assert_eq!(ok, "Hello from the fake engine. You said: hello");

    // Negative controls: no token and a wrong token both get 401.
    match run(&HttpEngine::new(&fake.addr)) {
        Err(EngineError::Http(s)) => assert!(s.starts_with("401"), "{s}"),
        r => panic!("no token: {r:?}"),
    }
    let wrong = load_bearer_token(&token_file(&model.dir.join("w"), WRONG, 0o600)).unwrap();
    match run(&HttpEngine::new(&fake.addr).with_bearer(wrong)) {
        Err(EngineError::Http(s)) => assert!(s.starts_with("401"), "{s}"),
        r => panic!("wrong token: {r:?}"),
    }
    assert_eq!(
        *fake.auth.lock().unwrap(),
        vec![
            Some(format!("Bearer {TOKEN}")),
            None,
            Some(format!("Bearer {WRONG}"))
        ]
    );
    // The engine never got a body it refused.
    assert_eq!(fake.seen.lock().unwrap().len(), 1);
}

#[test]
fn debug_of_an_engine_hides_the_token() {
    let model = model_dir("tok-debug");
    let t = load_bearer_token(&token_file(&model.dir, TOKEN, 0o600)).unwrap();
    let shown = format!("{:?}", HttpEngine::new("127.0.0.1:1").with_bearer(t));
    assert!(!shown.contains(&TOKEN[..16]), "{shown}");
}

fn free_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The real coordinator and volunteer binaries against `engine`, the
/// volunteer started with only `HOME=home` in its environment. Returns the
/// gateway's reply to one overflow request and the volunteer's log. The
/// gateway answers 200 before the volunteer's engine is called, so the
/// engine's verdict shows in the streamed text.
fn binaries_overflow(tag: &str, engine: &FakeEngine, home: &Path) -> (GatewayReply, String) {
    let model = model_dir(tag);
    let vol_bin = env!("CARGO_BIN_EXE_oh-infer-volunteer");
    let coord_bin = env!("CARGO_BIN_EXE_oh-infer-coordinator");
    let key_file = model.dir.join("volunteer.key");
    let init = Command::new(vol_bin)
        .args(["init", "--key-file", &path_str(&key_file)])
        .output()
        .unwrap();
    assert!(init.status.success());
    let vol_key = String::from_utf8(init.stdout).unwrap();
    let vol_key = vol_key
        .trim()
        .strip_prefix("volunteer key ")
        .unwrap()
        .to_string();
    let digest = oh_infer::protocol::hex(&model.digest);
    let (lv, la) = (free_port(), free_port());
    let mut coord = Kill(
        Command::new(coord_bin)
            .args([
                "--model-id",
                &model.name,
                "--model-digest",
                &digest,
                "--approve",
                &vol_key,
                "--listen-volunteers",
                &lv,
                "--listen-api",
                &la,
                "--state-dir",
                &path_str(&model.dir.join("state")),
                "--routing",
                "on",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut out = BufReader::new(coord.0.stdout.take().unwrap());
    let line = read_lines_until(&mut out, "coordinator key ");
    let coord_key = line
        .trim()
        .strip_prefix("coordinator key ")
        .unwrap()
        .to_string();
    read_lines_until(&mut out, "routing");
    let log = model.dir.join("volunteer.log");
    let _vol = Kill(
        Command::new(vol_bin)
            .args([
                "run",
                "--coordinator",
                &format!("http://{lv}/oh/v1/volunteer"),
                "--coordinator-key",
                &coord_key,
                "--model-digest",
                &digest,
                "--key-file",
                &path_str(&key_file),
                "--manifest",
                &path_str(&model.manifest),
                "--model-dir",
                &path_str(&model.dir),
                "--engine",
                &engine.addr,
            ])
            .env_clear()
            .env("HOME", home)
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let mut healthy = false;
    for _ in 0..200 {
        let (_, body) = get(&la, "/v1/status");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        if v["healthy"] == 1 {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(healthy, "volunteer never attested");
    let r = overflow(
        &la,
        "",
        r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#,
    );
    std::thread::sleep(Duration::from_millis(100));
    (r, std::fs::read_to_string(&log).unwrap())
}

#[test]
fn volunteer_binary_reads_the_wizard_token_from_home() {
    let home = model_dir("tok-home");
    token_file(&home.dir.join(".local/share/aienos"), TOKEN, 0o600);
    let engine = fake_engine_requiring(honest_reply, Some(TOKEN.into()));
    let (r, log) = binaries_overflow("tok-bin-ok", &engine, &home.dir);
    assert_eq!(r.status, 200, "{log}");
    assert_eq!(
        r.text, "Hello from the fake engine. You said: hi",
        "{r:?}\n{log}"
    );
    assert!(log.contains("engine bearer token loaded from"), "{log}");
    assert!(!log.contains(TOKEN), "the token reached the log");
    assert_eq!(
        engine.auth.lock().unwrap().as_slice(),
        &[Some(format!("Bearer {TOKEN}"))]
    );
}

#[test]
fn volunteer_binary_without_a_token_file_sends_none_and_says_so() {
    let home = model_dir("tok-none");
    let engine = fake_engine_requiring(honest_reply, Some(TOKEN.into()));
    let (r, log) = binaries_overflow("tok-bin-none", &engine, &home.dir);
    assert!(!r.text.contains("Hello from the fake engine"), "{r:?}");
    assert!(log.contains("engine answered HTTP 401"), "{log}");
    assert_eq!(log.matches("no engine bearer token at").count(), 1, "{log}");
    assert_eq!(engine.auth.lock().unwrap().as_slice(), &[None]);

    // The same volunteer against an engine that needs no token (the shipped
    // engine) still answers.
    let open = fake_engine(honest_reply);
    let (r, _) = binaries_overflow("tok-bin-open", &open, &home.dir);
    assert_eq!(r.text, "Hello from the fake engine. You said: hi", "{r:?}");
}

#[test]
fn volunteer_binary_refuses_a_token_others_can_read() {
    let home = model_dir("tok-0644");
    let vol_bin = env!("CARGO_BIN_EXE_oh-infer-volunteer");
    let key = path_str(&home.dir.join("k"));
    let init = Command::new(vol_bin)
        .args(["init", "--key-file", &key])
        .output()
        .unwrap();
    assert!(init.status.success());
    let run_with = |f: &Path| {
        Command::new(vol_bin)
            .args([
                "run",
                "--coordinator",
                "http://127.0.0.1:9/oh/v1/volunteer",
                "--coordinator-key",
                &"00".repeat(32),
                "--model-digest",
                &"00".repeat(32),
                "--manifest",
                "/nonexistent",
                "--model-dir",
                "/nonexistent",
                "--key-file",
                &key,
                "--engine-token-file",
                &path_str(f),
            ])
            .env_clear()
            .output()
            .unwrap()
    };
    let f = token_file(&home.dir.join("loose"), TOKEN, 0o644);
    let out = run_with(&f);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{err}");
    assert!(
        err.contains("refusing the engine token") && err.contains("0644"),
        "{err}"
    );
    assert!(!err.contains(TOKEN));

    // Control: the same token at 0600 passes the token check and the run
    // stops later, at the (missing) model, still exit 5 but not for the token.
    let f = token_file(&home.dir.join("tight"), TOKEN, 0o600);
    let out = run_with(&f);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{err}");
    assert!(err.contains("engine bearer token loaded from"), "{err}");
    assert!(err.contains("refusing to serve"), "{err}");
    assert!(!err.contains("refusing the engine token"), "{err}");
}
