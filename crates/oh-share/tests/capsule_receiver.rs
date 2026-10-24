//! Issue #34: the capsule receiver re-checks everything itself and keeps
//! data acceptance, claim reproduction and native qualification apart.

mod common;

use beacon_core::Keypair;
use common::*;
use oh_share::codec::{seal, CodecError, MAX_CAPSULE_BYTES};
use oh_share::*;

fn other_env(field: &str) -> ReceiverPolicy {
    let mut p = policy();
    match field {
        "abi" => p.environment.abi = "omega-abi-2".into(),
        "model" => p.environment.model = "other-model".into(),
        "precision" => p.environment.precision = "bf16".into(),
        "hardware" => p.environment.hardware = "gb10-sm121".into(),
        _ => unreachable!(),
    }
    p
}

#[test]
fn two_peers_publish_transfer_refuse_wrong_machine_accept_right_machine_revoke_ack() {
    let (mut owner, _) = owner();
    let mut right = recipient();
    let mut wrong = recipient_with(other_env("hardware"));
    owner.register_recipient(keys(&right));
    owner.register_recipient(keys(&wrong));
    let pkg = owner.create_private(spec("peer")).unwrap();
    for r in [&right, &wrong] {
        owner
            .grant(
                pkg,
                r.sign_key(),
                Uses(Uses::RETRIEVAL.0 | Uses::INDEX.0),
                LICENSE,
                T0 + 30 * DAY,
                vec![],
                T0,
            )
            .unwrap();
    }

    // Encrypted transfer: the sealed bytes carry no plaintext.
    let to_right = owner.publish(pkg, right.sign_key(), T0).unwrap();
    assert!(!contains(&to_right.bytes, SECRET_TRACE.as_bytes()));
    assert!(!contains(&to_right.bytes, b"fused_add"));

    let to_wrong = owner.publish(pkg, wrong.sign_key(), T0).unwrap();
    assert_eq!(
        wrong.receive_capsule(&to_wrong.bytes, T0 + 1).unwrap_err(),
        CapsuleRejection::IncompatibleEnvironment("hardware")
    );
    assert_eq!(
        wrong.serve(owner.owner_id(), pkg, T0 + 1).unwrap_err(),
        UseDenied::NotHeld
    );

    let accepted = right.receive_capsule(&to_right.bytes, T0 + 1).unwrap();
    assert_eq!(accepted.package_id, pkg);
    let oid = owner.owner_id();
    assert_eq!(
        right.serve(oid, pkg, T0 + 2).unwrap().program,
        payload("peer").program
    );
    let entry = right.index_entry(oid, pkg, T0 + 2).unwrap();
    assert_eq!(entry.capsule_id, accepted.capsule_id);
    assert!(
        !format!("{entry:?}").contains(SECRET_TRACE),
        "index carries metadata only"
    );

    // Accepting the data says nothing about the claim or native code.
    let q = right.qualification(oid, pkg).unwrap();
    assert!(q.data_accepted);
    assert_eq!(q.claim_reproduced, Stage::Untrusted);
    assert_eq!(q.native_qualified, Stage::Untrusted);
    // The receiver's own verifier may reproduce (the capsule asked for REPRODUCE)...
    right
        .record_reproduction(oid, pkg, true, "local-verifier", T0 + 3)
        .unwrap();
    // ...but native execution was never requested, so it cannot be qualified.
    assert_eq!(
        right
            .record_native_qualification(oid, pkg, true, "local-forge", T0 + 3)
            .unwrap_err(),
        UseDenied::CapabilityNotAllowed
    );
    let q = right.qualification(oid, pkg).unwrap();
    assert_eq!(
        q.claim_reproduced,
        Stage::Passed {
            verifier: "local-verifier".into()
        }
    );
    assert_eq!(q.native_qualified, Stage::Untrusted);

    // Revoke and ACK.
    owner.withdraw(pkg, Uses::ALL, T0 + 10).unwrap();
    let n = owner
        .outbound_notices(T0 + 10)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == right.sign_key())
        .unwrap();
    let ack = right.handle_notice(&n.bytes, T0 + 11).unwrap();
    assert!(matches!(
        owner.record_ack(&ack, T0 + 11),
        Ok(DeliveryStatus::Acknowledged { .. })
    ));
    assert_eq!(
        right.serve(oid, pkg, T0 + 12).unwrap_err(),
        UseDenied::Revoked
    );
    assert_eq!(
        right.index_entry(oid, pkg, T0 + 12).unwrap_err(),
        UseDenied::Revoked
    );
    assert_eq!(
        right
            .record_reproduction(oid, pkg, true, "local-verifier", T0 + 12)
            .unwrap_err(),
        UseDenied::Revoked
    );
}

#[test]
fn every_environment_field_must_match() {
    for field in ["abi", "model", "precision", "hardware"] {
        let kp = Keypair::generate();
        let mut r = recipient_with(other_env(field));
        let capsule = hand_capsule(&kp, &r, |_, _, _| {}, |_, _| {});
        assert_eq!(
            r.receive_capsule(&capsule, T0).unwrap_err(),
            CapsuleRejection::IncompatibleEnvironment(match field {
                "abi" => "abi",
                "model" => "model",
                "precision" => "precision",
                _ => "hardware",
            })
        );
    }
}

#[test]
fn baseline_hand_built_capsule_is_accepted() {
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(&kp, &r, |_, _, _| {}, |_, _| {});
    r.receive_capsule(&capsule, T0).unwrap();
}

fn rejects(
    pre: impl FnOnce(&mut OwnerConsent, &mut CapsuleHeader, &mut CapsulePayload),
    post: impl FnOnce(&mut CapsuleHeader, &mut CapsulePayload),
    now: u64,
) -> CapsuleRejection {
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(&kp, &r, pre, post);
    r.receive_capsule(&capsule, now).unwrap_err()
}

#[test]
fn edited_payload_is_a_digest_mismatch() {
    let err = rejects(
        |_, _, _| {},
        |_, p| p.outcome = "verified speedup 9.9x".into(),
        T0,
    );
    assert_eq!(err, CapsuleRejection::DigestMismatch);
}

#[test]
fn edited_header_is_a_bad_signature() {
    let err = rejects(|_, _, _| {}, |h, _| h.capabilities = Capabilities(3), T0);
    assert_eq!(err, CapsuleRejection::BadSignature);
}

#[test]
fn forged_signer_is_refused() {
    let attacker = Keypair::generate();
    // Consent by the owner, header re-signed by an attacker.
    let err = rejects(|_, _, _| {}, |h, _| h.sign_with(&attacker), T0);
    assert_eq!(err, CapsuleRejection::UnauthorizedSigner);
}

#[test]
fn forged_consent_is_refused() {
    let err = rejects(
        |c, _, _| {
            c.sig = vec![7u8; 64];
        },
        |_, _| {},
        T0,
    );
    assert_eq!(err, CapsuleRejection::ForgedConsent);
}

#[test]
fn amplified_consent_after_signing_is_refused() {
    // Consent signed for retrieval, then edited to add training.
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(
        &kp,
        &r,
        |c, _, _| {
            c.sign_with(&kp);
            c.uses = Uses(c.uses.0 | Uses::TRAINING.0);
        },
        |_, _| {},
    );
    assert_eq!(
        r.receive_capsule(&capsule, T0).unwrap_err(),
        CapsuleRejection::ForgedConsent
    );
}

#[test]
fn custodian_cannot_grant() {
    let custodian = Keypair::generate();
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(
        &kp,
        &r,
        |c, h, _| {
            c.custodians = vec![custodian.pubkey_bytes()];
            c.sign_with(&custodian);
            h.sign_with(&custodian);
        },
        |_, _| {},
    );
    assert_eq!(
        r.receive_capsule(&capsule, T0).unwrap_err(),
        CapsuleRejection::UnauthorizedSigner
    );
}

#[test]
fn stale_and_future_capsules_are_refused() {
    assert_eq!(
        rejects(|_, _, _| {}, |_, _| {}, T0 + 8 * DAY),
        CapsuleRejection::Expired
    );
    assert_eq!(
        rejects(|_, h, _| h.created_at = T0 + 3600, |_, _| {}, T0),
        CapsuleRejection::FromFuture
    );
    assert_eq!(
        rejects(|c, _, _| c.retention_end = T0, |_, _| {}, T0),
        CapsuleRejection::ConsentExpired
    );
}

#[test]
fn capsule_signed_before_a_known_retraction_is_stale() {
    let kp = Keypair::generate();
    let mut r = recipient();
    let oid = kp.pubkey_bytes();
    // The owner withdraws some other package at seq 5; this node enforces it.
    let mut n = RetractionNotice {
        version: 1,
        notice_id: rand::random(),
        owner_id: oid,
        signer: [0; 32],
        recipient: r.sign_key(),
        package_id: rand::random(),
        scope: Uses::ALL,
        seq: 5,
        issued_at: T0,
        retry_until: T0 + DAY,
        sig: vec![],
    };
    n.sign_with(&kp);
    r.handle_notice(&seal(&r.box_key(), &n.to_bytes().unwrap()).unwrap(), T0)
        .unwrap();
    let old = hand_capsule(&kp, &r, |_, h, _| h.revocation_head = 4, |_, _| {});
    assert_eq!(
        r.receive_capsule(&old, T0).unwrap_err(),
        CapsuleRejection::StaleRevocationHead
    );
    let fresh = hand_capsule(&kp, &r, |_, h, _| h.revocation_head = 5, |_, _| {});
    r.receive_capsule(&fresh, T0).unwrap();
}

#[test]
fn license_and_consent_scope_fail_closed() {
    assert_eq!(
        rejects(
            |c, _, _| c.license = "proprietary-unknown".into(),
            |_, _| {},
            T0
        ),
        CapsuleRejection::UnknownLicense("proprietary-unknown".into())
    );
    assert_eq!(
        rejects(|c, _, _| c.uses = Uses::INDEX, |_, _| {}, T0),
        CapsuleRejection::NoRetrievalConsent
    );
    assert_eq!(
        rejects(|c, _, _| c.uses = Uses(0x81), |_, _| {}, T0),
        CapsuleRejection::UnknownUses
    );
}

#[test]
fn external_effects_and_out_of_scope_capabilities_are_refused() {
    for effect in [
        Capabilities::NETWORK_EGRESS,
        Capabilities::FILE_WRITE,
        Capabilities::TOOL_CALL,
    ] {
        let caps = Capabilities(Capabilities::DATA_READ.0 | effect.0);
        assert_eq!(
            rejects(|_, h, _| h.capabilities = caps, |_, _| {}, T0),
            CapsuleRejection::ForbiddenCapability
        );
    }
    assert_eq!(
        rejects(
            |_, h, _| h.capabilities = Capabilities(0x100),
            |_, _| {},
            T0
        ),
        CapsuleRejection::UnknownCapability
    );
    // A receiver whose policy is data-only refuses a request to run native code.
    let kp = Keypair::generate();
    let mut strict = policy();
    strict.allowed_capabilities = Capabilities::DATA_READ;
    let mut r = recipient_with(strict);
    let capsule = hand_capsule(
        &kp,
        &r,
        |_, h, _| {
            h.capabilities =
                Capabilities(Capabilities::DATA_READ.0 | Capabilities::NATIVE_EXECUTE.0)
        },
        |_, _| {},
    );
    assert_eq!(
        r.receive_capsule(&capsule, T0).unwrap_err(),
        CapsuleRejection::CapabilityOutOfScope
    );
}

#[test]
fn fake_independent_evidence_is_recorded_but_never_trusted() {
    let kp = Keypair::generate();
    let fake_verifier = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(
        &kp,
        &r,
        |_, h, _| {
            h.evidence = Evidence {
                tier: EvidenceTier::IndependentlyVerified,
                verifier: fake_verifier.pubkey_bytes(),
                claim: "T_real=1.0 T=1.0 J=1.0, verified".into(),
            };
            h.capabilities =
                Capabilities(Capabilities::DATA_READ.0 | Capabilities::NATIVE_EXECUTE.0);
        },
        |_, _| {},
    );
    let a = r.receive_capsule(&capsule, T0).unwrap();
    let q = r.qualification(a.owner_id, a.package_id).unwrap();
    assert_eq!(q.claim_reproduced, Stage::Untrusted);
    assert_eq!(q.native_qualified, Stage::Untrusted);
    // The receiver's own native check fails; the capsule's claim changes nothing.
    r.record_native_qualification(a.owner_id, a.package_id, false, "local-forge", T0)
        .unwrap();
    assert_eq!(
        r.qualification(a.owner_id, a.package_id)
            .unwrap()
            .native_qualified,
        Stage::Failed {
            verifier: "local-forge".into()
        }
    );
    // REPRODUCE was not requested, so reproduction cannot be recorded either.
    assert_eq!(
        r.record_reproduction(a.owner_id, a.package_id, true, "x", T0)
            .unwrap_err(),
        UseDenied::CapabilityNotAllowed
    );
}

#[test]
fn negative_results_are_carried_as_data() {
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(
        &kp,
        &r,
        |_, h, p| {
            h.evidence.tier = EvidenceTier::Negative;
            p.outcome = "replication failed: 0.97x on cpu-aarch64".into();
        },
        |_, _| {},
    );
    let a = r.receive_capsule(&capsule, T0).unwrap();
    assert_eq!(
        r.index_entry(a.owner_id, a.package_id, T0)
            .unwrap()
            .evidence_tier,
        EvidenceTier::Negative
    );
}

#[test]
fn duplicate_and_replayed_capsules_are_refused() {
    let kp = Keypair::generate();
    let mut r = recipient();
    let capsule = hand_capsule(&kp, &r, |_, _, _| {}, |_, _| {});
    r.receive_capsule(&capsule, T0).unwrap();
    assert_eq!(
        r.receive_capsule(&capsule, T0 + 1).unwrap_err(),
        CapsuleRejection::Duplicate
    );
    // Same package, same terms, new capsule id: still a duplicate, not a second copy.
    let (mut owner, _) = owner();
    let mut r2 = recipient();
    owner.register_recipient(keys(&r2));
    let pkg = owner.create_private(spec("dup")).unwrap();
    owner
        .grant(
            pkg,
            r2.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![],
            T0,
        )
        .unwrap();
    r2.receive_capsule(&owner.publish(pkg, r2.sign_key(), T0).unwrap().bytes, T0)
        .unwrap();
    assert_eq!(
        r2.receive_capsule(&owner.publish(pkg, r2.sign_key(), T0).unwrap().bytes, T0)
            .unwrap_err(),
        CapsuleRejection::Duplicate
    );
    assert!(r2.serve(owner.owner_id(), pkg, T0).is_ok());
}

#[test]
fn poisoned_payload_with_secrets_is_refused() {
    let err = rejects(
        |_, _, p| p.trace = "export api_key = \"abcdefghijklmnop1234567890\"".into(),
        |_, _| {},
        T0,
    );
    assert!(matches!(err, CapsuleRejection::Firewall(_)), "{err:?}");
    // The owner side refuses to even create such a package.
    let (mut owner, _) = owner();
    let mut s = spec("leak");
    s.payload.trace = "token ghp_abcdefghijklmnopqrstuvwxyz0123456789".into();
    assert!(matches!(
        owner.create_private(s),
        Err(OwnerError::Firewall(_))
    ));
}

#[test]
fn overbudget_wrong_key_and_misaddressed_capsules_are_refused() {
    let kp = Keypair::generate();
    let mut r = recipient();
    let other = recipient();
    // Over the size budget: refused before any decryption.
    let huge = vec![0u8; MAX_CAPSULE_BYTES as usize + 1024];
    assert_eq!(
        r.receive_capsule(&huge, T0).unwrap_err(),
        CapsuleRejection::Envelope(CodecError::TooLarge(MAX_CAPSULE_BYTES))
    );
    // Sealed to someone else: does not open.
    let for_other = hand_capsule(&kp, &other, |_, _, _| {}, |_, _| {});
    assert_eq!(
        r.receive_capsule(&for_other, T0).unwrap_err(),
        CapsuleRejection::Envelope(CodecError::Undecryptable)
    );
    // Sealed to me, but the consent names another recipient.
    let other_key = other.sign_key();
    let misaddressed = hand_capsule(&kp, &r, |c, _, _| c.recipient = other_key, |_, _| {});
    assert_eq!(
        r.receive_capsule(&misaddressed, T0).unwrap_err(),
        CapsuleRejection::WrongRecipient
    );
    // Garbage that opens but does not decode.
    let junk = seal(&r.box_key(), b"not a capsule").unwrap();
    assert!(matches!(
        r.receive_capsule(&junk, T0).unwrap_err(),
        CapsuleRejection::Malformed(_)
    ));
}

#[test]
fn no_cross_owner_leak() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();
    let mut r = recipient();
    let pkg: PackageId = rand::random();
    let c1 = hand_capsule(&kp1, &r, |c, _, _| c.package_id = pkg, |_, _| {});
    let a1 = r.receive_capsule(&c1, T0).unwrap();
    // Owner 2 asking for owner 1's package id gets nothing.
    assert_eq!(
        r.serve(kp2.pubkey_bytes(), pkg, T0).unwrap_err(),
        UseDenied::NotHeld
    );
    // Owner 2 publishing under the same package id does not collide with owner 1.
    let c2 = hand_capsule(&kp2, &r, |c, _, _| c.package_id = pkg, |_, _| {});
    r.receive_capsule(&c2, T0).unwrap();
    assert!(r.serve(a1.owner_id, pkg, T0).is_ok());
    // Owner 2 cannot sign as owner 1.
    let impostor = hand_capsule(
        &kp2,
        &r,
        |c, _, _| c.owner_id = kp1.pubkey_bytes(),
        |_, _| {},
    );
    assert_eq!(
        r.receive_capsule(&impostor, T0).unwrap_err(),
        CapsuleRejection::UnauthorizedSigner
    );
}
