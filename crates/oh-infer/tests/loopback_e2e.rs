//! Loopback end to end with a fake engine: the real coordinator and
//! volunteer binaries, a gateway client, and a printed transcript.
//! Run with `--nocapture` to see the transcript.

mod common;

use common::*;
use std::io::BufReader;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

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

#[test]
fn binaries_answer_a_visitor_through_a_volunteer() {
    let model = model_dir("e2e");
    let engine = fake_engine(honest_reply);
    let key_file = model.dir.join("volunteer.key");
    let vol_bin = env!("CARGO_BIN_EXE_oh-infer-volunteer");
    let coord_bin = env!("CARGO_BIN_EXE_oh-infer-coordinator");

    let init = Command::new(vol_bin)
        .args(["init", "--key-file", &path_str(&key_file)])
        .output()
        .unwrap();
    assert!(init.status.success());
    let key_line = String::from_utf8(init.stdout).unwrap();
    let vol_key = key_line
        .trim()
        .strip_prefix("volunteer key ")
        .unwrap()
        .to_string();
    println!(
        "[volunteer] $ oh-infer-volunteer init --key-file volunteer.key\n[volunteer] {}",
        key_line.trim()
    );

    let digest = oh_infer::protocol::hex(&model.digest);
    let verify = Command::new(vol_bin)
        .args([
            "verify",
            "--manifest",
            &path_str(&model.manifest),
            "--model-dir",
            &path_str(&model.dir),
            "--model-digest",
            &digest,
        ])
        .output()
        .unwrap();
    assert!(verify.status.success());
    println!(
        "[volunteer] {}",
        String::from_utf8_lossy(&verify.stdout).trim()
    );

    let (lv, la) = (free_port(), free_port());
    let state = model.dir.join("state");
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
                &path_str(&state),
                "--sample-rate",
                "1",
                "--probation-sample-rate",
                "1",
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
    println!("[coordinator] {}", line.trim());
    println!(
        "[coordinator] {}",
        read_lines_until(&mut out, "routing").trim()
    );

    // The pinned values travel in a config file, as the SI bundle ships them.
    let conf = model.dir.join("lend.conf");
    std::fs::write(
        &conf,
        format!(
            "# pinned by the release\ncoordinator http://{lv}/oh/v1/volunteer\ncoordinator-key {coord_key}\nmodel-digest {digest}\n"
        ),
    )
    .unwrap();
    let _vol = Kill(
        Command::new(vol_bin)
            .args([
                "run",
                "--config",
                &path_str(&conf),
                "--key-file",
                &path_str(&key_file),
                "--manifest",
                &path_str(&model.manifest),
                "--model-dir",
                &path_str(&model.dir),
                "--engine",
                &engine.addr,
            ])
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let mut healthy = false;
    for _ in 0..200 {
        let (_, body) = get(&la, "/v1/status");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        if v["healthy"] == 1 {
            println!("[gateway] GET /v1/status -> {body}");
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(healthy, "volunteer never attested");

    let body = r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"What is Open Humanity?"}],"max_tokens":64}"#;
    println!("[gateway] POST /v1/overflow {body}");
    let r = overflow(&la, "", body);
    assert_eq!(r.status, 200, "{r:?}");
    let hdr = |n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(hdr("x-oh-volunteer"), vol_key[..16]);
    assert_eq!(hdr("x-oh-model"), model.name);
    for (k, v) in r.headers.iter().filter(|(k, _)| k.starts_with("x-oh-")) {
        println!("[gateway] < {k}: {v}");
    }
    println!("[gateway] streamed text: {:?}", r.text);
    assert_eq!(
        r.text,
        "Hello from the fake engine. You said: What is Open Humanity?"
    );
    assert!(r.raw.contains("\"answered_by\":\"volunteer\""));
    assert!(r.raw.ends_with("data: [DONE]\n\n"));

    // The engine on the volunteer saw greedy, seeded decoding and the
    // coordinator's public system prompt plus the visitor's message only.
    let seen = engine.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["temperature"], 0);
    assert_eq!(seen[0]["seed"], 0);
    println!("[volunteer engine] received {}", seen[0]);

    // Sampled replay: the gateway pulls the job and answers with Drake's
    // engine output (here the same fake model), then gets the verdict.
    let (st, task) = get(&la, "/v1/replay/next");
    assert_eq!(st, 200);
    let task: serde_json::Value = serde_json::from_str(&task).unwrap();
    let reference = honest_reply(&task["request"]);
    let (st, verdict) = post(
        &la,
        "/v1/replay/result",
        &serde_json::json!({"replay_id": task["replay_id"], "output": reference}).to_string(),
    );
    println!("[gateway] replay {} -> {verdict}", task["replay_id"]);
    assert_eq!(st, 200);
    assert!(verdict.contains("\"verdict\":\"match\""));
    let (_, status) = get(&la, "/v1/status");
    println!("[gateway] GET /v1/status -> {status}");
}

#[test]
fn routing_off_sends_nothing_to_volunteers() {
    let model = model_dir("off");
    let engine = fake_engine(honest_reply);
    let kp = beacon_core::Keypair::generate();
    let mut cfg = test_config(&model, &[kp.pubkey_bytes()]);
    cfg.routing_enabled = false;
    let running = start(cfg);
    let (_h, jobs) = spawn_volunteer(&running, &model, kp, &engine.addr);
    wait_healthy(&running.coord, 1);
    let r = overflow(
        &running.api_addr,
        "",
        r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert_eq!(r.status, 503);
    assert_eq!(r.error.as_deref(), Some("volunteer routing is off"));
    assert!(jobs.lock().unwrap().is_empty());
    assert!(engine.seen.lock().unwrap().is_empty());
}

#[test]
fn no_volunteer_means_503() {
    let model = model_dir("none");
    let running = start(test_config(&model, &[]));
    let r = overflow(
        &running.api_addr,
        "",
        r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert_eq!(r.status, 503);
    assert_eq!(r.error.as_deref(), Some("no volunteer is available"));
}
