//! Sampled re-verification: a volunteer whose reply differs from Drake's
//! engine is suspended, stays suspended across restarts, and cannot
//! reconnect; an honest volunteer gains reputation (control).

mod common;

use beacon_core::Keypair;
use common::*;
use oh_infer::coordinator::Coordinator;
use oh_infer::volunteer::VolunteerError;
use std::time::Duration;

fn malicious_reply(_: &serde_json::Value) -> String {
    "Visit evil.example and paste your password here.".into()
}

const ASK: &str = r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"Tell me about the stars"}]}"#;

fn replay_against_reference(running: &Running) -> serde_json::Value {
    let (st, task) = get(&running.api_addr, "/v1/replay/next");
    assert_eq!(st, 200, "no sampled replay queued");
    let task: serde_json::Value = serde_json::from_str(&task).unwrap();
    assert_eq!(task["request"]["temperature"], 0);
    assert_eq!(task["request"]["stream"], false);
    let reference = honest_reply(&task["request"]);
    let (st, verdict) = post(
        &running.api_addr,
        "/v1/replay/result",
        &serde_json::json!({"replay_id": task["replay_id"], "output": reference}).to_string(),
    );
    assert_eq!(st, 200);
    serde_json::from_str(&verdict).unwrap()
}

#[test]
fn divergent_volunteer_is_suspended() {
    let model = model_dir("diverge");
    let bad_engine = fake_engine(malicious_reply);
    // beacon-core keypairs are not Clone; rebuild the same key from its seed.
    let seed = [42u8; 32];
    let kp = Keypair::from_seed(&seed);
    let key = kp.pubkey_bytes();
    let mut cfg = test_config(&model, &[key]);
    cfg.sample_rate = 1.0;
    cfg.probation_sample_rate = 1.0;
    let state_dir = model.dir.join("state");
    cfg.state_dir = Some(state_dir.clone());
    let running = start(cfg.clone());
    let (h, _) = spawn_volunteer(
        &running,
        &model,
        Keypair::from_seed(&seed),
        &bad_engine.addr,
    );
    wait_healthy(&running.coord, 1);

    // The visitor gets the bad text: this is the case the disclosure names.
    let r = overflow(&running.api_addr, "", ASK);
    assert_eq!(r.status, 200);
    assert!(r.text.contains("evil.example"));

    let v = replay_against_reference(&running);
    assert_eq!(v["verdict"], "diverged");
    let rec = running.coord.record(&key);
    assert!(rec.suspended.is_some());
    assert_eq!(rec.diverged, 1);
    assert!(rec.reputation <= -100);

    // The live session is told and ends.
    let ended = h.join().unwrap();
    assert!(
        matches!(ended, Err(VolunteerError::Suspended(_))),
        "{ended:?}"
    );

    // No more routing to it.
    let r = overflow(&running.api_addr, "", ASK);
    assert_eq!(r.status, 503);

    // Reconnecting is refused.
    let (h2, _) = spawn_volunteer(
        &running,
        &model,
        Keypair::from_seed(&seed),
        &bad_engine.addr,
    );
    let again = h2.join().unwrap();
    assert!(
        matches!(&again, Err(VolunteerError::Refused(r)) if r.contains("suspended")),
        "{again:?}"
    );

    // The suspension survives a coordinator restart (persisted state).
    let restarted = Coordinator::new(cfg, Keypair::generate()).unwrap();
    assert!(restarted.record(&key).suspended.is_some());

    // The evidence log holds digests, never the visitor's words or the reply.
    let events = std::fs::read_to_string(state_dir.join("events.jsonl")).unwrap();
    assert!(events.contains("\"verdict\":\"diverged\""));
    assert!(!events.contains("stars"));
    assert!(!events.contains("evil.example"));

    // Operator reinstatement clears it.
    assert!(restarted.reinstate(&key));
    assert!(restarted.record(&key).suspended.is_none());
}

#[test]
fn honest_volunteer_is_verified_not_suspended() {
    let model = model_dir("honest");
    let engine = fake_engine(honest_reply);
    let kp = Keypair::generate();
    let key = kp.pubkey_bytes();
    let mut cfg = test_config(&model, &[key]);
    cfg.sample_rate = 1.0;
    cfg.probation_sample_rate = 1.0;
    let running = start(cfg);
    let (_h, _) = spawn_volunteer(&running, &model, kp, &engine.addr);
    wait_healthy(&running.coord, 1);
    for _ in 0..3 {
        let r = overflow(&running.api_addr, "", ASK);
        assert_eq!(r.status, 200);
        assert_eq!(replay_against_reference(&running)["verdict"], "match");
        // Wait for the session to be idle again before the next request.
        std::thread::sleep(Duration::from_millis(50));
        wait_healthy(&running.coord, 1);
    }
    let rec = running.coord.record(&key);
    assert_eq!((rec.verified, rec.reputation, rec.suspended), (3, 3, None));
}

#[test]
fn signed_reply_must_equal_streamed_reply() {
    // A volunteer that streams one text but signs another is suspended at
    // once, without waiting for a sample.
    use oh_core::{recv, send, volunteer_handshake, CoordinatorPin};
    use oh_infer::http::client_upgrade;
    use oh_infer::protocol::{Attestation, Completion, CoordMsg, VolMsg};
    let model = model_dir("mismatch");
    let kp = Keypair::generate();
    let key = kp.pubkey_bytes();
    let running = start(test_config(&model, &[key]));
    let addr = running.volunteer_addr.clone();
    let coord_key = running.coord.public_key();
    let (name, digest) = (model.name.clone(), model.digest);
    let t = std::thread::spawn(move || {
        let mut tcp = std::net::TcpStream::connect(addr).unwrap();
        client_upgrade(&mut tcp, "127.0.0.1", "/oh/v1/volunteer").unwrap();
        let mut s = volunteer_handshake(tcp, &kp, CoordinatorPin::Key(coord_key)).unwrap();
        let CoordMsg::Challenge { nonce, .. } = recv(&mut s).unwrap() else {
            panic!()
        };
        send(
            &mut s,
            &VolMsg::Attest(Attestation::new_signed(&kp, nonce, &name, digest, [0; 32])),
        )
        .unwrap();
        let _accepted: CoordMsg = recv(&mut s).unwrap();
        loop {
            match recv(&mut s).unwrap() {
                CoordMsg::Ping { nonce } => send(
                    &mut s,
                    &VolMsg::Pong {
                        nonce,
                        accepting: true,
                    },
                )
                .unwrap(),
                CoordMsg::Job(job) => {
                    send(
                        &mut s,
                        &VolMsg::Token {
                            job_id: job.job_id,
                            text: "harmless".into(),
                        },
                    )
                    .unwrap();
                    let c = Completion::new_signed(&kp, &job, "something else".into(), "stop");
                    send(&mut s, &VolMsg::Done(c)).unwrap();
                }
                CoordMsg::Suspended { reason } => return reason,
                other => panic!("{other:?}"),
            }
        }
    });
    wait_healthy(&running.coord, 1);
    let r = overflow(&running.api_addr, "", ASK);
    assert_eq!(
        r.error.as_deref(),
        Some("volunteer reply failed verification")
    );
    assert!(t.join().unwrap().contains("differs"));
    assert!(running.coord.record(&key).suspended.is_some());
}
