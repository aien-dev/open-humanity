//! Privacy: no memory, contact or visitor-identity field can reach a
//! volunteer. Requests that carry one are refused whole; requests without
//! the visitor's consent are refused; what a volunteer does receive is only
//! the public system prompt and the anonymous conversation text.

mod common;

use beacon_core::Keypair;
use common::*;
use oh_infer::protocol::{ChatMessage, Job};

/// Marker strings planted in every forbidden field. None may ever appear in
/// anything the volunteer or its engine receives.
const MARKERS: [&str; 6] = [
    "VISITORKEY-7f3a",
    "MEMORY-likes-astronomy",
    "CONTACT-ada@example.org",
    "NAME-Ada-Lovelace",
    "IP-203.0.113.9",
    "PHONE-555-0100",
];

#[test]
fn memory_and_contact_fields_never_reach_a_volunteer() {
    let model = model_dir("privacy");
    let engine = fake_engine(honest_reply);
    let kp = Keypair::generate();
    let running = start(test_config(&model, &[kp.pubkey_bytes()]));
    let (_h, jobs) = spawn_volunteer(&running, &model, kp, &engine.addr);
    wait_healthy(&running.coord, 1);
    let api = &running.api_addr;
    let msgs = r#"[{"role":"user","content":"hello"}]"#;

    // Each forbidden field is refused with 400 before any routing.
    let forbidden_bodies = [
        format!(
            r#"{{"volunteer_consent":true,"messages":{msgs},"visitor_key":"{}"}}"#,
            MARKERS[0]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":{msgs},"memory":["{}"]}}"#,
            MARKERS[1]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":{msgs},"contact":{{"email":"{}"}}}}"#,
            MARKERS[2]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":{msgs},"name":"{}"}}"#,
            MARKERS[3]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":[{{"role":"user","content":"hi","name":"{}"}}]}}"#,
            MARKERS[3]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":[{{"role":"system","content":"Known facts: {}"}},{{"role":"user","content":"hi"}}]}}"#,
            MARKERS[1]
        ),
        format!(
            r#"{{"volunteer_consent":true,"messages":[{{"role":"tool","content":"{}"}},{{"role":"user","content":"hi"}}]}}"#,
            MARKERS[5]
        ),
    ];
    for b in &forbidden_bodies {
        let r = overflow(api, "", b);
        assert_eq!(r.status, 400, "accepted a forbidden request: {b} -> {r:?}");
    }

    // Identity headers are refused with 403, even with a clean body.
    let clean = format!(r#"{{"volunteer_consent":true,"messages":{msgs}}}"#);
    for h in [
        format!("X-Allen-Key: {}\r\n", MARKERS[0]),
        format!("Cookie: allen={}\r\n", MARKERS[0]),
        format!("X-Forwarded-For: {}\r\n", MARKERS[4]),
        format!("X-Real-IP: {}\r\n", MARKERS[4]),
    ] {
        let r = overflow(api, &h, &clean);
        assert_eq!(r.status, 403, "accepted identity header {h:?}: {r:?}");
    }

    // No visitor consent, no volunteer.
    let r = overflow(
        api,
        "",
        &format!(r#"{{"volunteer_consent":false,"messages":{msgs}}}"#),
    );
    assert_eq!(r.status, 403);
    let r = overflow(api, "", &format!(r#"{{"messages":{msgs}}}"#));
    assert_eq!(r.status, 400, "consent must be explicit");

    assert!(
        jobs.lock().unwrap().is_empty(),
        "a refused request reached the volunteer"
    );
    assert!(engine.seen.lock().unwrap().is_empty());

    // A clean, consented request goes through.
    let r = overflow(
        api,
        "",
        r#"{"volunteer_consent":true,"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"Hi! I'm Allen."},{"role":"user","content":"what can you do?"}]}"#,
    );
    assert_eq!(r.status, 200, "{r:?}");

    let jobs = jobs.lock().unwrap().clone();
    assert_eq!(jobs.len(), 1);
    // Exhaustive destructuring: adding a field to Job breaks this test,
    // which forces a privacy review of the new field.
    let Job {
        job_id: _,
        model_id,
        messages,
        max_tokens: _,
        seed: _,
    } = jobs[0].clone();
    assert_eq!(model_id, model.name);
    let texts: Vec<&str> = messages
        .iter()
        .map(|ChatMessage { role: _, content }| content.as_str())
        .collect();
    assert_eq!(
        texts,
        [
            "You are Allen, Drake's public assistant.",
            "hello",
            "Hi! I'm Allen.",
            "what can you do?"
        ]
    );

    // Everything the volunteer's engine received, as raw JSON: only the
    // expected keys and no marker anywhere.
    let seen = engine.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let mut keys: Vec<&String> = seen[0].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "max_tokens",
            "messages",
            "model",
            "seed",
            "stream",
            "temperature",
            "top_p"
        ]
    );
    for m in seen[0]["messages"].as_array().unwrap() {
        let mut k: Vec<&String> = m.as_object().unwrap().keys().collect();
        k.sort();
        assert_eq!(k, ["content", "role"]);
    }
    let everything = format!("{:?}{}", jobs, seen[0]);
    for m in MARKERS {
        assert!(!everything.contains(m), "{m} reached the volunteer");
    }
}

#[test]
fn negative_control_markers_are_detectable() {
    // The marker check above would catch a leak: a job built with a
    // marker in its text is found by the same comparison.
    let job = Job {
        job_id: [0; 16],
        model_id: "m".into(),
        messages: vec![ChatMessage {
            role: oh_infer::protocol::Role::User,
            content: format!("hi {}", MARKERS[2]),
        }],
        max_tokens: 1,
        seed: 0,
    };
    let everything = format!("{:?}", vec![job]);
    assert!(MARKERS.iter().any(|m| everything.contains(m)));
}
