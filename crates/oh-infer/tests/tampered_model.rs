//! Negative controls for the model hash: modified weights are refused on
//! the volunteer before it can connect, and a volunteer that attests a
//! different model hash is refused by the coordinator.

mod common;

use beacon_core::Keypair;
use common::*;
use oh_core::{recv, send, volunteer_handshake, CoordinatorPin};
use oh_infer::http::client_upgrade;
use oh_infer::model::{verify_model, ModelError};
use oh_infer::protocol::{Attestation, CoordMsg, VolMsg};
use std::net::TcpStream;

#[test]
fn modified_weight_file_is_refused_before_serving() {
    let model = model_dir("tamper-file");
    assert!(verify_model(&model.manifest, &model.dir, Some(&model.digest)).is_ok());
    let mut bytes = std::fs::read(model.dir.join("layers-0.safetensors")).unwrap();
    bytes[100] ^= 1;
    std::fs::write(model.dir.join("layers-0.safetensors"), bytes).unwrap();
    assert_eq!(
        verify_model(&model.manifest, &model.dir, Some(&model.digest)),
        Err(ModelError::WrongHash("layers-0.safetensors".into()))
    );

    // The real binary exits 5 and never connects.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_oh-infer-volunteer"))
        .args([
            "verify",
            "--manifest",
            &path_str(&model.manifest),
            "--model-dir",
            &path_str(&model.dir),
            "--model-digest",
            &oh_infer::protocol::hex(&model.digest),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not match the manifest"));
}

#[test]
fn edited_manifest_is_refused_against_the_pin() {
    let model = model_dir("tamper-manifest");
    let pin = model.digest;
    // Re-hash a modified file into a new manifest: internally consistent,
    // but not the pinned model.
    std::fs::write(model.dir.join("layers-0.safetensors"), vec![8u8; 4096]).unwrap();
    let m = oh_infer::model::write_manifest(
        &model.name,
        &model.dir,
        &["config.json", "layers-0.safetensors"],
    )
    .unwrap();
    std::fs::write(&model.manifest, m).unwrap();
    assert!(matches!(
        verify_model(&model.manifest, &model.dir, Some(&pin)),
        Err(ModelError::WrongManifest { .. })
    ));
}

/// Drives the protocol by hand, as a modified agent would, attesting
/// `digest`. Returns the coordinator's answer.
fn attest_with(running: &Running, kp: &Keypair, model_name: &str, digest: [u8; 32]) -> CoordMsg {
    let mut tcp = TcpStream::connect(&running.volunteer_addr).unwrap();
    client_upgrade(&mut tcp, "127.0.0.1", "/oh/v1/volunteer").unwrap();
    let mut s =
        volunteer_handshake(tcp, kp, CoordinatorPin::Key(running.coord.public_key())).unwrap();
    let nonce = match recv(&mut s).unwrap() {
        CoordMsg::Challenge { nonce, .. } => nonce,
        other => panic!("expected a challenge, got {other:?}"),
    };
    let att = Attestation::new_signed(kp, nonce, model_name, digest, [0; 32]);
    send(&mut s, &VolMsg::Attest(att)).unwrap();
    recv(&mut s).unwrap()
}

#[test]
fn coordinator_refuses_a_tampered_model_hash() {
    let model = model_dir("tamper-attest");
    let kp = Keypair::generate();
    let running = start(test_config(&model, &[kp.pubkey_bytes()]));

    let mut tampered = model.digest;
    tampered[0] ^= 0xff;
    match attest_with(&running, &kp, &model.name, tampered) {
        CoordMsg::Refused { reason } => {
            assert!(reason.contains("is not the pinned"), "{reason}");
        }
        other => panic!("tampered hash was not refused: {other:?}"),
    }
    assert_eq!(running.coord.status().connected, 0);

    // Control: the same key with the pinned hash is accepted.
    match attest_with(&running, &kp, &model.name, model.digest) {
        CoordMsg::Accepted { max_inflight } => assert_eq!(max_inflight, 1),
        other => panic!("pinned hash was not accepted: {other:?}"),
    }
}

#[test]
fn unregistered_key_is_refused() {
    let model = model_dir("unregistered");
    let running = start(test_config(&model, &[]));
    let kp = Keypair::generate();
    let mut tcp = TcpStream::connect(&running.volunteer_addr).unwrap();
    client_upgrade(&mut tcp, "127.0.0.1", "/oh/v1/volunteer").unwrap();
    let mut s =
        volunteer_handshake(tcp, &kp, CoordinatorPin::Key(running.coord.public_key())).unwrap();
    match recv(&mut s).unwrap() {
        CoordMsg::Refused { reason } => assert!(reason.contains("not registered")),
        other => panic!("unregistered key got {other:?}"),
    }
}

#[test]
fn honest_agent_with_other_model_never_attests() {
    let model = model_dir("other-model");
    let kp = Keypair::generate();
    let running = start(test_config(&model, &[kp.pubkey_bytes()]));
    let other = model_dir("other-model-2");
    std::fs::write(other.dir.join("layers-0.safetensors"), vec![9u8; 4096]).unwrap();
    let m = oh_infer::model::write_manifest(
        &other.name,
        &other.dir,
        &["config.json", "layers-0.safetensors"],
    )
    .unwrap();
    let other_digest: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&m).into()
    };
    let cfg = oh_infer::volunteer::VolunteerConfig {
        keypair: kp,
        coordinator_key: running.coord.public_key(),
        host: "127.0.0.1".into(),
        path: "/oh/v1/volunteer".into(),
        model_id: other.name.clone(),
        model_digest: other_digest,
        engine_digest: [0; 32],
        pause_file: None,
    };
    let engine = oh_infer::engine::HttpEngine::new("127.0.0.1:9");
    let s = TcpStream::connect(&running.volunteer_addr).unwrap();
    let r = oh_infer::volunteer::run_session(s, &cfg, &engine, &mut |_| {});
    assert!(
        matches!(
            r,
            Err(oh_infer::volunteer::VolunteerError::ModelMismatch { .. })
        ),
        "{r:?}"
    );
    assert_eq!(running.coord.status().connected, 0);
}
