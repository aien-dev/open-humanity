//! Issue #33: owner-signed withdrawal, per-recipient acks and the
//! future-use gate, over real loopback TCP where delivery matters.

mod common;

use beacon_core::Keypair;
use common::*;
use oh_share::codec::seal;
use oh_share::net::{deliver_pending, RoundError};
use oh_share::*;
use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(500);

fn all_uses() -> Uses {
    Uses(Uses::RETRIEVAL.0 | Uses::INDEX.0 | Uses::TRAINING.0)
}

/// Owner, two recipients, one package granted and delivered to both.
fn shared_to_two(
    uses_a: Uses,
    uses_b: Uses,
) -> (OwnerLedger, [u8; 32], Recipient, Recipient, PackageId) {
    shared_with(recipient(), recipient(), uses_a, uses_b)
}

fn shared_with(
    mut a: Recipient,
    mut b: Recipient,
    uses_a: Uses,
    uses_b: Uses,
) -> (OwnerLedger, [u8; 32], Recipient, Recipient, PackageId) {
    let (mut owner, seed) = owner();
    owner.register_recipient(keys(&a));
    owner.register_recipient(keys(&b));
    let pkg = owner.create_private(spec("two")).unwrap();
    owner
        .grant(
            pkg,
            a.sign_key(),
            uses_a,
            LICENSE,
            T0 + 30 * DAY,
            vec![],
            T0,
        )
        .unwrap();
    owner
        .grant(
            pkg,
            b.sign_key(),
            uses_b,
            LICENSE,
            T0 + 30 * DAY,
            vec![],
            T0,
        )
        .unwrap();
    for r in [&mut a, &mut b] {
        let sealed = owner.publish(pkg, r.sign_key(), T0).unwrap();
        r.receive_capsule(&sealed.bytes, T0).unwrap();
    }
    (owner, seed, a, b, pkg)
}

#[test]
fn two_recipients_withdraw_offline_then_replay_with_signed_acks() {
    let (mut owner, _, mut a, b, pkg) = shared_to_two(all_uses(), Uses::RETRIEVAL);
    let oid = owner.owner_id();
    let (a_key, b_key) = (a.sign_key(), b.sign_key());

    // Retrieval works before withdrawal; recipient A trains checkpoint C1.
    assert_eq!(a.serve(oid, pkg, T0 + 1).unwrap().trace, SECRET_TRACE);
    assert!(b.serve(oid, pkg, T0 + 1).is_ok());
    let c1 = [1u8; 16];
    a.begin_training(oid, pkg, c1, T0 + 2).unwrap();
    assert_eq!(a.checkpoint_status(c1), Some(CheckpointStatus::Clean));

    // Withdraw with no network at all: the local gate closes at once.
    let receipt = owner.withdraw(pkg, Uses::ALL, T0 + 10).unwrap();
    assert_eq!(receipt.recipients.len(), 2);
    assert_eq!(
        owner.publish(pkg, a_key, T0 + 11).unwrap_err(),
        OwnerError::Withdrawn
    );
    assert_eq!(
        owner
            .grant(
                pkg,
                a_key,
                Uses::RETRIEVAL,
                LICENSE,
                T0 + DAY,
                vec![],
                T0 + 11
            )
            .unwrap_err(),
        OwnerError::Withdrawn
    );
    let view = &owner.view()[0];
    assert!(!view.payload_retained);
    assert!(view
        .recipients
        .iter()
        .all(|r| r.retraction == Some(DeliveryStatus::Pending { attempts: 0 })));

    // Round 1: A online, B offline. Only the two registered recipients are contacted.
    let a = Arc::new(Mutex::new(a));
    let b = Arc::new(Mutex::new(b));
    let (a_addr, a_srv) = serve(a.clone(), 1, T0 + 20);
    let b_offline = offline_addr();
    let contacted = Mutex::new(BTreeSet::new());
    let resolve = |k: &Key| -> Option<SocketAddr> {
        contacted.lock().unwrap().insert(*k);
        if *k == a_key {
            Some(a_addr)
        } else if *k == b_key {
            Some(b_offline)
        } else {
            None
        }
    };
    let round = deliver_pending(&mut owner, resolve, TIMEOUT, T0 + 20).unwrap();
    a_srv.join().unwrap();
    assert_eq!(round.len(), 2);
    assert_eq!(
        *contacted.lock().unwrap(),
        BTreeSet::from([a_key, b_key]),
        "no transmission beyond the registered, granted recipients"
    );
    assert!(matches!(
        owner.delivery_status(pkg, a_key),
        Some(DeliveryStatus::Acknowledged {
            scope: Uses::ALL,
            ..
        })
    ));
    assert_eq!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Pending { attempts: 1 })
    );
    let b_round = round.iter().find(|r| r.recipient == b_key).unwrap();
    assert!(matches!(b_round.outcome, Err(RoundError::Delivery(_))));

    // A now refuses every future use; the trained checkpoint is quarantined, not unlearned.
    {
        let a = a.lock().unwrap();
        assert_eq!(a.serve(oid, pkg, T0 + 21).unwrap_err(), UseDenied::Revoked);
        assert_eq!(
            a.index_entry(oid, pkg, T0 + 21).unwrap_err(),
            UseDenied::Revoked
        );
        assert_eq!(
            a.authorize(oid, pkg, UseAction::Republish, T0 + 21)
                .unwrap_err(),
            UseDenied::Revoked
        );
        assert_eq!(
            a.checkpoint_status(c1),
            Some(CheckpointStatus::Quarantined {
                erasure: ErasureStatus::NotVerifiablyErased
            })
        );
    }
    let mut a_locked = a.lock().unwrap();
    assert_eq!(
        a_locked
            .begin_training(oid, pkg, [2u8; 16], T0 + 21)
            .unwrap_err(),
        UseDenied::Revoked
    );
    drop(a_locked);
    // B has not heard yet and still serves: reported honestly as pending.
    assert!(b.lock().unwrap().serve(oid, pkg, T0 + 21).is_ok());

    // Round 2: B comes back inside the window; the pending notice replays.
    let (b_addr, b_srv) = serve(b.clone(), 1, T0 + DAY);
    let round = deliver_pending(&mut owner, |_| Some(b_addr), TIMEOUT, T0 + DAY).unwrap();
    b_srv.join().unwrap();
    assert_eq!(
        round.len(),
        1,
        "A is acknowledged and is not contacted again"
    );
    assert!(matches!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Acknowledged { .. })
    ));
    assert_eq!(
        b.lock().unwrap().serve(oid, pkg, T0 + DAY).unwrap_err(),
        UseDenied::Revoked
    );

    // The owner view: ack statuses, the reported checkpoint, and no erasure claim.
    let view = &owner.view()[0];
    let a_view = view
        .recipients
        .iter()
        .find(|r| r.recipient == a_key)
        .unwrap();
    assert_eq!(a_view.influenced_checkpoints, vec![c1]);
    assert!(a_view.training_consent);
    let b_view = view
        .recipients
        .iter()
        .find(|r| r.recipient == b_key)
        .unwrap();
    assert!(!b_view.training_consent);
    assert_eq!(
        view.uncontrolled_copies,
        Some(ErasureStatus::NotVerifiablyErased)
    );
    assert_eq!(
        view.trained_weights,
        Some(ErasureStatus::NotVerifiablyErased)
    );
    assert!(owner.outbound_notices(T0 + DAY).unwrap().is_empty());
}

#[test]
fn unresponsive_recipient_is_pending_then_unreachable_then_reissued() {
    let (mut owner, _, _a, b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    let b_key = b.sign_key();
    owner.withdraw(pkg, Uses::ALL, T0 + 10).unwrap();

    // A listener that accepts and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let hold = std::thread::spawn(move || {
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(silent.accept().unwrap().0);
        }
        std::thread::sleep(Duration::from_millis(1200));
    });
    deliver_pending(
        &mut owner,
        |_| Some(silent_addr),
        Duration::from_millis(200),
        T0 + 20,
    )
    .unwrap();
    hold.join().unwrap();
    assert_eq!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Pending { attempts: 1 })
    );

    // The retry window (7 days) closes: unreachable, never "done".
    let late = T0 + 10 + 7 * DAY + 1;
    assert!(owner.outbound_notices(late).unwrap().is_empty());
    assert!(matches!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Unreachable { attempts: 1, .. })
    ));

    // The owner re-signs; the recipient, now answering, acknowledges.
    owner.reissue(pkg, b_key, late).unwrap();
    let b = Arc::new(Mutex::new(b));
    let (addr, srv) = serve(b.clone(), 1, late);
    let round =
        deliver_pending(&mut owner, |k| (*k == b_key).then_some(addr), TIMEOUT, late).unwrap();
    srv.join().unwrap();
    assert!(round
        .iter()
        .any(|r| r.recipient == b_key && r.outcome.is_ok()));
    assert!(matches!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Acknowledged { .. })
    ));
}

#[test]
fn malicious_recipient_answers_cannot_forge_acknowledgement_or_erasure() {
    let (b_rec, b_seed) = recipient_seeded();
    let (mut owner, _, a, b, pkg) =
        shared_with(recipient(), b_rec, Uses::RETRIEVAL, Uses::RETRIEVAL);
    let (a_key, b_key) = (a.sign_key(), b.sign_key());
    owner.withdraw(pkg, Uses::ALL, T0 + 10).unwrap();
    let notices = owner.outbound_notices(T0 + 10).unwrap();
    let to_a = notices
        .iter()
        .find(|n| n.recipient == a_key)
        .unwrap()
        .clone();
    let to_b = notices
        .iter()
        .find(|n| n.recipient == b_key)
        .unwrap()
        .clone();

    // A genuine ack from A, used as a template for forgeries.
    let mut a = a;
    let genuine_a = a.handle_notice(&to_a.bytes, T0 + 11).unwrap();
    let template = RetractionAck::from_bytes(&genuine_a).unwrap();

    // 1. An attacker key signs an ack naming B as the recipient.
    let attacker = Keypair::generate();
    let mut forged = template.clone();
    forged.package_id = pkg;
    forged.notice_digest = to_b.notice_digest;
    forged.sign_with(&attacker);
    forged.recipient = b_key;
    assert_eq!(
        owner.record_ack(&forged.to_bytes().unwrap(), T0 + 12),
        Err(AckError::BadSignature)
    );

    // 2. A's real, validly signed ack replayed as B's answer.
    let mut replayed = template.clone();
    replayed.recipient = b_key;
    assert_eq!(
        owner.record_ack(&replayed.to_bytes().unwrap(), T0 + 12),
        Err(AckError::UnknownNotice)
    );

    // 3. A spoofed "everything deleted" confirmation: there is no such
    //    outcome in the format, so the bytes do not even decode.
    let mut spoof = template.clone();
    spoof.recipient = b_key;
    spoof.notice_digest = to_b.notice_digest;
    let mut bytes = spoof.to_bytes().unwrap();
    let outcome_at = 2 + 32 + 32 + 16 + 8 + 32; // version, digest, owner, package, seq, recipient
    assert_eq!(&bytes[outcome_at..outcome_at + 4], &0u32.to_le_bytes());
    bytes[outcome_at..outcome_at + 4].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(owner.record_ack(&bytes, T0 + 12), Err(AckError::Malformed));

    // 4. Over TCP: a malicious recipient answers with the forged ack.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let reply = forged.to_bytes().unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = oh_share::codec::read_frame(&mut s, 1 << 20).unwrap();
        oh_share::codec::write_frame(&mut s, &reply, 1 << 20).unwrap();
    });
    let round = deliver_pending(
        &mut owner,
        |k| (*k == b_key).then_some(addr),
        TIMEOUT,
        T0 + 13,
    )
    .unwrap();
    srv.join().unwrap();
    let b_round = round.iter().find(|r| r.recipient == b_key).unwrap();
    assert_eq!(
        b_round.outcome,
        Err(RoundError::BadAck(AckError::BadSignature))
    );
    assert_eq!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Pending { attempts: 1 })
    );

    // 5. A dishonest B, with its real key, acks less than the notice asked for.
    let mut b = b;
    let mut short =
        RetractionAck::from_bytes(&b.handle_notice(&to_b.bytes, T0 + 14).unwrap()).unwrap();
    short.outcome = AckOutcome::FutureUseBlocked {
        scope: Uses::RETRIEVAL,
    };
    short.sign_with(&Keypair::from_seed(&b_seed));
    assert!(short.signature_valid());
    assert_eq!(
        owner.record_ack(&short.to_bytes().unwrap(), T0 + 14),
        Err(AckError::ScopeShort)
    );
    assert_eq!(
        owner.delivery_status(pkg, b_key),
        Some(DeliveryStatus::Pending { attempts: 1 })
    );

    // Remote erasure is never reported, whatever acks arrived.
    owner.record_ack(&genuine_a, T0 + 15).unwrap();
    let view = &owner.view()[0];
    assert_eq!(
        view.uncontrolled_copies,
        Some(ErasureStatus::NotVerifiablyErased)
    );
}

#[test]
fn withdraw_before_training_vs_after_checkpoint() {
    let (mut owner, _, mut a, mut b, pkg) = shared_to_two(all_uses(), all_uses());
    let oid = owner.owner_id();

    // B trains before the withdrawal; A has not trained yet.
    let ckpt = [9u8; 16];
    b.begin_training(oid, pkg, ckpt, T0 + 5).unwrap();
    owner.withdraw(pkg, Uses::ALL, T0 + 10).unwrap();
    for n in owner.outbound_notices(T0 + 10).unwrap() {
        let r = if n.recipient == a.sign_key() {
            &mut a
        } else {
            &mut b
        };
        let ack = r.handle_notice(&n.bytes, T0 + 11).unwrap();
        owner.record_ack(&ack, T0 + 11).unwrap();
    }

    // Before training: refused, and no checkpoint was ever influenced.
    let fresh = [8u8; 16];
    assert_eq!(
        a.begin_training(oid, pkg, fresh, T0 + 12).unwrap_err(),
        UseDenied::Revoked
    );
    assert_eq!(a.checkpoint_status(fresh), None);

    // After a checkpoint: quarantined, and reported to the owner as not verifiably erased.
    assert_eq!(
        b.checkpoint_status(ckpt),
        Some(CheckpointStatus::Quarantined {
            erasure: ErasureStatus::NotVerifiablyErased
        })
    );
    let view = &owner.view()[0];
    let bv = view
        .recipients
        .iter()
        .find(|r| r.recipient == b.sign_key())
        .unwrap();
    assert_eq!(bv.influenced_checkpoints, vec![ckpt]);
    let av = view
        .recipients
        .iter()
        .find(|r| r.recipient == a.sign_key())
        .unwrap();
    assert!(av.influenced_checkpoints.is_empty());
    assert_eq!(
        view.trained_weights,
        Some(ErasureStatus::NotVerifiablyErased)
    );
}

#[test]
fn stale_keys_and_identity_rotation() {
    let (mut owner, old_seed, mut a, _b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    let oid = owner.owner_id();
    let old = Keypair::from_seed(&old_seed);
    let new_seed: [u8; 32] = rand::random();
    let rotation = owner
        .rotate_key(Keypair::from_seed(&new_seed), T0 + 5)
        .unwrap();
    assert!(rotation.signatures_valid());

    let sealed_rotation = owner.sealed_rotation(a.sign_key()).unwrap().unwrap();
    a.handle_rotation(&sealed_rotation).unwrap();
    assert_eq!(
        a.handle_rotation(&sealed_rotation),
        Err(RotationError::Replay)
    );

    // A rotation the attacker signs alone is refused.
    let attacker = Keypair::generate();
    let bogus = KeyRotation::new_signed(oid, &attacker, &Keypair::generate(), 99, T0 + 6);
    let bogus = seal(&a.box_key(), &bogus.to_bytes().unwrap()).unwrap();
    assert_eq!(a.handle_rotation(&bogus), Err(RotationError::NotCurrent));

    // A notice signed with the retired key is refused as stale.
    let mut stale = RetractionNotice {
        version: 1,
        notice_id: rand::random(),
        owner_id: oid,
        signer: [0; 32],
        recipient: a.sign_key(),
        package_id: pkg,
        scope: Uses::ALL,
        seq: 50,
        issued_at: T0 + 6,
        retry_until: T0 + DAY,
        sig: vec![],
    };
    stale.sign_with(&old);
    let ack = a
        .handle_notice(
            &seal(&a.box_key(), &stale.to_bytes().unwrap()).unwrap(),
            T0 + 6,
        )
        .unwrap();
    assert_eq!(
        RetractionAck::from_bytes(&ack).unwrap().outcome,
        AckOutcome::Rejected(NoticeRejectReason::StaleKey)
    );
    assert!(a.serve(oid, pkg, T0 + 6).is_ok());

    // A capsule signed with the retired key is refused as stale.
    let capsule = hand_capsule(&old, &a, |_, _, _| {}, |_, _| {});
    assert_eq!(
        a.receive_capsule(&capsule, T0 + 6).unwrap_err(),
        CapsuleRejection::StaleKey
    );

    // The owner's real withdrawal, signed with the new key, is enforced.
    owner.withdraw(pkg, Uses::ALL, T0 + 7).unwrap();
    let n = owner
        .outbound_notices(T0 + 7)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    let ack = a.handle_notice(&n.bytes, T0 + 7).unwrap();
    assert!(matches!(
        owner.record_ack(&ack, T0 + 7),
        Ok(DeliveryStatus::Acknowledged { .. })
    ));
    assert_eq!(a.serve(oid, pkg, T0 + 8).unwrap_err(), UseDenied::Revoked);
}

#[test]
fn notice_withdrawn_before_rotation_is_resigned_and_still_accepted() {
    let (mut owner, _, mut a, _b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    owner.withdraw(pkg, Uses::ALL, T0 + 5).unwrap();
    owner.rotate_key(Keypair::generate(), T0 + 6).unwrap();
    a.handle_rotation(&owner.sealed_rotation(a.sign_key()).unwrap().unwrap())
        .unwrap();
    let n = owner
        .outbound_notices(T0 + 7)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    let ack = a.handle_notice(&n.bytes, T0 + 7).unwrap();
    assert!(matches!(
        owner.record_ack(&ack, T0 + 7),
        Ok(DeliveryStatus::Acknowledged { .. })
    ));
}

#[test]
fn malicious_publish_race_never_sends_after_withdrawal() {
    let (mut owner, _) = owner();
    let r = recipient();
    owner.register_recipient(keys(&r));
    let pkg = owner.create_private(spec("race")).unwrap();
    owner
        .grant(
            pkg,
            r.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![],
            T0,
        )
        .unwrap();
    let r_key = r.sign_key();
    let shared = Arc::new(Mutex::new(owner));

    let publishers: Vec<_> = (0..4)
        .map(|_| {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let mut sent = Vec::new();
                let mut refused = 0u32;
                for _ in 0..200 {
                    match shared.lock().unwrap().publish(pkg, r_key, T0) {
                        Ok(s) => sent.push(s),
                        Err(OwnerError::Withdrawn) => refused += 1,
                        Err(e) => panic!("unexpected {e}"),
                    }
                }
                (sent, refused)
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(2));
    let receipt = shared
        .lock()
        .unwrap()
        .withdraw(pkg, Uses::ALL, T0 + 1)
        .unwrap();
    let mut sent = Vec::new();
    let mut refused = 0;
    for p in publishers {
        let (s, f) = p.join().unwrap();
        sent.extend(s);
        refused += f;
    }
    assert_eq!(sent.len() as u32 + refused, 800);
    assert!(
        sent.iter().all(|s| s.event < receipt.event),
        "every admitted send precedes the withdrawal"
    );
    assert!(shared.lock().unwrap().publish(pkg, r_key, T0 + 2).is_err());

    // A capsule admitted before the withdrawal but delivered after the
    // recipient enforced it (a relay holding it back) is refused.
    let mut r = r;
    let notice = shared
        .lock()
        .unwrap()
        .outbound_notices(T0 + 2)
        .unwrap()
        .pop()
        .unwrap();
    r.handle_notice(&notice.bytes, T0 + 2).unwrap();
    if let Some(late) = sent.last() {
        assert_eq!(
            r.receive_capsule(&late.bytes, T0 + 3).unwrap_err(),
            CapsuleRejection::Revoked
        );
    }

    // The same holds when the notice reaches a recipient that never got the package.
    let (mut owner2, seed2) = common::owner();
    let mut r2 = recipient();
    owner2.register_recipient(keys(&r2));
    let pkg2 = owner2.create_private(spec("race2")).unwrap();
    owner2
        .grant(
            pkg2,
            r2.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![],
            T0,
        )
        .unwrap();
    let held_back = owner2.publish(pkg2, r2.sign_key(), T0).unwrap();
    owner2.withdraw(pkg2, Uses::ALL, T0 + 1).unwrap();
    let n2 = owner2.outbound_notices(T0 + 1).unwrap().pop().unwrap();
    let ack = r2.handle_notice(&n2.bytes, T0 + 1).unwrap();
    assert!(owner2.record_ack(&ack, T0 + 1).is_ok());
    assert_eq!(
        r2.receive_capsule(&held_back.bytes, T0 + 2).unwrap_err(),
        CapsuleRejection::Revoked
    );
    let _ = seed2;
}

#[test]
fn expired_consent_refused_on_both_sides() {
    let (mut owner, _) = owner();
    let mut r = recipient();
    owner.register_recipient(keys(&r));
    let pkg = owner.create_private(spec("exp")).unwrap();
    owner
        .grant(
            pkg,
            r.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + 100,
            vec![],
            T0,
        )
        .unwrap();
    let sealed = owner.publish(pkg, r.sign_key(), T0).unwrap();
    r.receive_capsule(&sealed.bytes, T0 + 1).unwrap();
    assert!(r.serve(owner.owner_id(), pkg, T0 + 99).is_ok());
    assert_eq!(
        r.serve(owner.owner_id(), pkg, T0 + 100).unwrap_err(),
        UseDenied::ConsentExpired
    );
    assert_eq!(
        owner.publish(pkg, r.sign_key(), T0 + 100).unwrap_err(),
        OwnerError::ConsentExpired
    );
}

#[test]
fn cross_tenant_notices_do_not_touch_other_recipients_or_owners() {
    let (owner_x, _, mut a, mut b, pkg_x) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    let oid_x = owner_x.owner_id();
    let _ = owner_x;

    // Owner Y shares a package with A too.
    let (mut owner_y, y_seed) = owner();
    owner_y.register_recipient(keys(&a));
    let pkg_y = owner_y.create_private(spec("y")).unwrap();
    owner_y
        .grant(
            pkg_y,
            a.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![],
            T0,
        )
        .unwrap();
    a.receive_capsule(&owner_y.publish(pkg_y, a.sign_key(), T0).unwrap().bytes, T0)
        .unwrap();

    // Y withdraws: only Y's package at A is affected.
    owner_y.withdraw(pkg_y, Uses::ALL, T0 + 5).unwrap();
    let n = owner_y.outbound_notices(T0 + 5).unwrap().pop().unwrap();
    // Delivered to the wrong tenant B (sealed to A, so B cannot even open it).
    assert!(b.handle_notice(&n.bytes, T0 + 5).is_none());
    // The same owner-signed notice re-sealed to B by a relay: B opens it, but it names A.
    let mut wrong_tenant = RetractionNotice {
        version: 1,
        notice_id: rand::random(),
        owner_id: owner_y.owner_id(),
        signer: [0; 32],
        recipient: a.sign_key(),
        package_id: pkg_y,
        scope: Uses::ALL,
        seq: 1,
        issued_at: T0 + 5,
        retry_until: T0 + DAY,
        sig: vec![],
    };
    wrong_tenant.sign_with(&Keypair::from_seed(&y_seed));
    let to_b = seal(&b.box_key(), &wrong_tenant.to_bytes().unwrap()).unwrap();
    let ack = RetractionAck::from_bytes(&b.handle_notice(&to_b, T0 + 5).unwrap()).unwrap();
    assert_eq!(
        ack.outcome,
        AckOutcome::Rejected(NoticeRejectReason::WrongRecipient)
    );

    a.handle_notice(&n.bytes, T0 + 6).unwrap();
    assert_eq!(
        a.serve(owner_y.owner_id(), pkg_y, T0 + 6).unwrap_err(),
        UseDenied::Revoked
    );
    assert!(
        a.serve(oid_x, pkg_x, T0 + 6).is_ok(),
        "owner X's grant is untouched"
    );
    assert!(b.serve(oid_x, pkg_x, T0 + 6).is_ok());

    // Y tries to withdraw X's package by naming X as owner: unauthorized.
    let y_key = Keypair::generate();
    let mut hijack = RetractionNotice {
        version: 1,
        notice_id: rand::random(),
        owner_id: oid_x,
        signer: [0; 32],
        recipient: a.sign_key(),
        package_id: pkg_x,
        scope: Uses::ALL,
        seq: 1,
        issued_at: T0 + 7,
        retry_until: T0 + DAY,
        sig: vec![],
    };
    hijack.sign_with(&y_key);
    let ack = a
        .handle_notice(
            &seal(&a.box_key(), &hijack.to_bytes().unwrap()).unwrap(),
            T0 + 7,
        )
        .unwrap();
    assert_eq!(
        RetractionAck::from_bytes(&ack).unwrap().outcome,
        AckOutcome::Rejected(NoticeRejectReason::UnauthorizedSigner)
    );
    assert!(a.serve(oid_x, pkg_x, T0 + 7).is_ok());
}

#[test]
fn unauthorized_representative_refused_declared_custodian_accepted() {
    let (mut owner, _) = owner();
    let mut r = recipient();
    owner.register_recipient(keys(&r));
    let custodian = Keypair::generate();
    let pkg = owner.create_private(spec("cust")).unwrap();
    owner
        .grant(
            pkg,
            r.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![custodian.pubkey_bytes()],
            T0,
        )
        .unwrap();
    r.receive_capsule(&owner.publish(pkg, r.sign_key(), T0).unwrap().bytes, T0)
        .unwrap();
    let oid = owner.owner_id();
    let notice_by = |kp: &Keypair| {
        let mut n = RetractionNotice {
            version: 1,
            notice_id: rand::random(),
            owner_id: oid,
            signer: [0; 32],
            recipient: r.sign_key(),
            package_id: pkg,
            scope: Uses::ALL,
            seq: 1,
            issued_at: T0 + 1,
            retry_until: T0 + DAY,
            sig: vec![],
        };
        n.sign_with(kp);
        seal(&r.box_key(), &n.to_bytes().unwrap()).unwrap()
    };
    let stranger = notice_by(&Keypair::generate());
    let by_custodian = notice_by(&custodian);

    let ack = RetractionAck::from_bytes(&r.handle_notice(&stranger, T0 + 1).unwrap()).unwrap();
    assert_eq!(
        ack.outcome,
        AckOutcome::Rejected(NoticeRejectReason::UnauthorizedSigner)
    );
    assert!(r.serve(oid, pkg, T0 + 1).is_ok());

    let ack = RetractionAck::from_bytes(&r.handle_notice(&by_custodian, T0 + 2).unwrap()).unwrap();
    assert_eq!(
        ack.outcome,
        AckOutcome::FutureUseBlocked { scope: Uses::ALL }
    );
    assert_eq!(r.serve(oid, pkg, T0 + 2).unwrap_err(), UseDenied::Revoked);
}

#[test]
fn corrupted_notices_never_acknowledge() {
    let (mut owner, seed, mut a, _b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    let oid = owner.owner_id();
    owner.withdraw(pkg, Uses::ALL, T0 + 5).unwrap();
    let n = owner
        .outbound_notices(T0 + 5)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();

    // A flipped bit in transit: the envelope does not open, nothing is answered.
    let mut flipped = n.bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(a.handle_notice(&flipped, T0 + 6).is_none());
    // Truncated and oversized envelopes are also dropped.
    assert!(a.handle_notice(&n.bytes[..20], T0 + 6).is_none());
    assert!(a.handle_notice(&vec![0u8; 1 << 16], T0 + 6).is_none());

    // A notice edited after signing (scope narrowed) and re-sealed: bad signature.
    let owner_kp = Keypair::from_seed(&seed);
    let mut edited = RetractionNotice {
        version: 1,
        notice_id: rand::random(),
        owner_id: oid,
        signer: [0; 32],
        recipient: a.sign_key(),
        package_id: pkg,
        scope: Uses::ALL,
        seq: 1,
        issued_at: T0 + 6,
        retry_until: T0 + DAY,
        sig: vec![],
    };
    edited.sign_with(&owner_kp);
    edited.scope = Uses::INDEX;
    let ack = a
        .handle_notice(
            &seal(&a.box_key(), &edited.to_bytes().unwrap()).unwrap(),
            T0 + 6,
        )
        .unwrap();
    let ack_msg = RetractionAck::from_bytes(&ack).unwrap();
    assert_eq!(
        ack_msg.outcome,
        AckOutcome::Rejected(NoticeRejectReason::BadSignature)
    );
    assert!(a.serve(oid, pkg, T0 + 6).is_ok());
    // That signed rejection names a notice the owner never sent: ignored.
    assert_eq!(owner.record_ack(&ack, T0 + 6), Err(AckError::UnknownNotice));
    assert_eq!(
        owner.delivery_status(pkg, a.sign_key()),
        Some(DeliveryStatus::Pending { attempts: 0 })
    );

    // Unknown scope bits fail closed.
    let mut odd = edited.clone();
    odd.scope = Uses(0x80);
    odd.sign_with(&owner_kp);
    let ack = a
        .handle_notice(
            &seal(&a.box_key(), &odd.to_bytes().unwrap()).unwrap(),
            T0 + 6,
        )
        .unwrap();
    assert_eq!(
        RetractionAck::from_bytes(&ack).unwrap().outcome,
        AckOutcome::Rejected(NoticeRejectReason::UnknownScope)
    );
}

#[test]
fn repeated_notice_is_idempotent() {
    let (mut owner, _, mut a, _b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    owner.withdraw(pkg, Uses::ALL, T0 + 5).unwrap();
    let n = owner
        .outbound_notices(T0 + 5)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    let first = a.handle_notice(&n.bytes, T0 + 6).unwrap();
    let again = a.handle_notice(&n.bytes, T0 + 9).unwrap();
    assert_eq!(
        first, again,
        "a replay gets the same signed ack and changes nothing"
    );
    assert_eq!(a.tombstones().len(), 1);
    owner.record_ack(&first, T0 + 9).unwrap();
    assert!(matches!(
        owner.record_ack(&again, T0 + 10),
        Ok(DeliveryStatus::Acknowledged { .. })
    ));
    // Withdrawing the same scope again issues nothing new.
    let r1 = owner.receipt(pkg).unwrap();
    assert_eq!(owner.withdraw(pkg, Uses::TRAINING, T0 + 11).unwrap(), r1);
}

#[test]
fn contradictory_consent_quarantines_the_package() {
    let (owner_ledger, seed) = owner();
    let _ = owner_ledger;
    let kp = Keypair::from_seed(&seed);
    let mut r = recipient();
    let pkg: PackageId = rand::random();
    let first = hand_capsule(&kp, &r, |c, _, _| c.package_id = pkg, |_, _| {});
    let second = hand_capsule(
        &kp,
        &r,
        |c, _, _| {
            c.package_id = pkg;
            c.uses = Uses(Uses::RETRIEVAL.0 | Uses::TRAINING.0);
        },
        |_, _| {},
    );
    r.receive_capsule(&first, T0).unwrap();
    assert_eq!(
        r.receive_capsule(&second, T0).unwrap_err(),
        CapsuleRejection::ContradictoryConsent
    );
    let oid = kp.pubkey_bytes();
    assert_eq!(r.serve(oid, pkg, T0).unwrap_err(), UseDenied::Quarantined);
    assert_eq!(
        r.begin_training(oid, pkg, [1; 16], T0).unwrap_err(),
        UseDenied::Quarantined
    );
}

#[test]
fn family_archive_consent_is_not_public_learning_consent() {
    let (mut owner, _) = owner();
    let mut family = recipient();
    owner.register_recipient(keys(&family));
    let pkg = owner.create_private(spec("family")).unwrap();
    let archive = Uses(Uses::RETRIEVAL.0 | Uses::ARCHIVE.0);
    owner
        .grant(
            pkg,
            family.sign_key(),
            archive,
            LICENSE,
            T0 + 365 * DAY,
            vec![],
            T0,
        )
        .unwrap();
    family
        .receive_capsule(
            &owner.publish(pkg, family.sign_key(), T0).unwrap().bytes,
            T0,
        )
        .unwrap();
    let oid = owner.owner_id();
    assert!(family.authorize(oid, pkg, UseAction::Archive, T0).is_ok());
    assert_eq!(
        family
            .authorize(oid, pkg, UseAction::Index, T0)
            .unwrap_err(),
        UseDenied::NotConsented
    );
    assert_eq!(
        family.begin_training(oid, pkg, [3; 16], T0).unwrap_err(),
        UseDenied::NotConsented
    );
    assert_eq!(
        family
            .authorize(oid, pkg, UseAction::Republish, T0)
            .unwrap_err(),
        UseDenied::NotConsented
    );
    assert!(!owner.view()[0].recipients[0].training_consent);
    assert_eq!(owner.view()[0].trained_weights, None);
}

#[test]
fn nothing_leaves_for_unregistered_or_ungranted_recipients() {
    let (mut owner, _) = owner();
    let registered = recipient();
    let stranger = recipient();
    owner.register_recipient(keys(&registered));
    let pkg = owner.create_private(spec("priv")).unwrap();
    assert_eq!(owner.view()[0].state, PackageState::Private);
    assert_eq!(
        owner.publish(pkg, registered.sign_key(), T0).unwrap_err(),
        OwnerError::NotGranted
    );
    assert_eq!(
        owner.publish(pkg, stranger.sign_key(), T0).unwrap_err(),
        OwnerError::UnregisteredRecipient
    );
    assert_eq!(
        owner
            .grant(
                pkg,
                stranger.sign_key(),
                Uses::RETRIEVAL,
                LICENSE,
                T0 + DAY,
                vec![],
                T0
            )
            .unwrap_err(),
        OwnerError::UnregisteredRecipient
    );
    // Withdrawing a never-published package notifies only the granted recipient.
    owner
        .grant(
            pkg,
            registered.sign_key(),
            Uses::RETRIEVAL,
            LICENSE,
            T0 + DAY,
            vec![],
            T0,
        )
        .unwrap();
    owner.withdraw(pkg, Uses::ALL, T0 + 1).unwrap();
    let out = owner.outbound_notices(T0 + 1).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].recipient, registered.sign_key());
    assert_eq!(
        owner.view()[0].uncontrolled_copies,
        None,
        "nothing was ever sent"
    );
}

#[test]
fn receipts_tombstones_and_notices_carry_no_content() {
    let (mut owner, _, mut a, _b, pkg) = shared_to_two(Uses::RETRIEVAL, Uses::RETRIEVAL);
    let content_digest = payload("two").digest();
    let receipt = owner.withdraw(pkg, Uses::ALL, T0 + 5).unwrap();
    let n = owner
        .outbound_notices(T0 + 5)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    // On the wire the notice is sealed: no ids, no text, no digest in clear.
    assert!(!contains(&n.bytes, &pkg));
    assert!(!contains(&n.bytes, &owner.owner_id()));
    assert!(!contains(&n.bytes, SECRET_TRACE.as_bytes()));
    assert!(!contains(&n.bytes, &content_digest));
    let ack = a.handle_notice(&n.bytes, T0 + 6).unwrap();
    assert!(!contains(&ack, SECRET_TRACE.as_bytes()));
    assert!(!contains(&ack, &content_digest));
    let receipt_text = format!("{receipt:?}");
    let tomb_text = format!("{:?}", a.tombstones());
    let digest_text = format!("{content_digest:?}");
    for text in [&receipt_text, &tomb_text] {
        assert!(!text.contains(SECRET_TRACE));
        assert!(!text.contains(&digest_text[1..digest_text.len() - 1]));
    }
    assert!(!owner.view()[0].payload_retained);
}

#[test]
fn partial_withdrawal_of_training_only() {
    let (mut owner, _, mut a, _b, pkg) = shared_to_two(all_uses(), Uses::RETRIEVAL);
    let oid = owner.owner_id();
    owner.withdraw(pkg, Uses::TRAINING, T0 + 5).unwrap();
    let n = owner
        .outbound_notices(T0 + 5)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    owner
        .record_ack(&a.handle_notice(&n.bytes, T0 + 6).unwrap(), T0 + 6)
        .unwrap();
    assert!(a.serve(oid, pkg, T0 + 6).is_ok());
    assert_eq!(
        a.begin_training(oid, pkg, [4; 16], T0 + 6).unwrap_err(),
        UseDenied::Revoked
    );
    // No new sends at all after any withdrawal; widening issues new notices.
    assert_eq!(
        owner.publish(pkg, a.sign_key(), T0 + 7).unwrap_err(),
        OwnerError::Withdrawn
    );
    let wider = owner.withdraw(pkg, Uses::ALL, T0 + 8).unwrap();
    assert_eq!(wider.scope, Uses::ALL);
    let n = owner
        .outbound_notices(T0 + 8)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    owner
        .record_ack(&a.handle_notice(&n.bytes, T0 + 9).unwrap(), T0 + 9)
        .unwrap();
    assert_eq!(a.serve(oid, pkg, T0 + 9).unwrap_err(), UseDenied::Revoked);
}

/// Encoded sizes, checked independently (Wolfram Language):
/// notice 227 B, sealed notice 295 B, ack 223 + 16 n B for n listed
/// checkpoints, so the 128-checkpoint ack is 2271 B under the 4096 B cap.
#[test]
fn control_message_sizes_are_pinned_and_ack_lists_are_bounded() {
    let (mut owner, _, mut a, _b, pkg) = shared_to_two(all_uses(), Uses::RETRIEVAL);
    let oid = owner.owner_id();
    for i in 0..200u32 {
        let mut ckpt = [0u8; 16];
        ckpt[..4].copy_from_slice(&i.to_le_bytes());
        a.begin_training(oid, pkg, ckpt, T0 + 1).unwrap();
    }
    owner.withdraw(pkg, Uses::ALL, T0 + 5).unwrap();
    let n = owner
        .outbound_notices(T0 + 5)
        .unwrap()
        .into_iter()
        .find(|n| n.recipient == a.sign_key())
        .unwrap();
    assert_eq!(n.bytes.len(), 295);
    let ack = a.handle_notice(&n.bytes, T0 + 6).unwrap();
    assert_eq!(ack.len(), 223 + 16 * MAX_LISTED_CHECKPOINTS);
    assert_eq!(ack.len(), 2271);
    let parsed = RetractionAck::from_bytes(&ack).unwrap();
    assert_eq!(parsed.influenced_checkpoints.len(), MAX_LISTED_CHECKPOINTS);
    assert_eq!(parsed.influenced_total, 200);
    owner.record_ack(&ack, T0 + 6).unwrap();
    let view = &owner.view()[0];
    let av = view
        .recipients
        .iter()
        .find(|r| r.recipient == a.sign_key())
        .unwrap();
    assert_eq!(av.influenced_total, 200);
    assert_eq!(
        view.trained_weights,
        Some(ErasureStatus::NotVerifiablyErased)
    );

    // A notice in the clear is 227 bytes; an ack with nothing trained is 223.
    let mut fresh = recipient();
    let (mut o2, _) = common::owner();
    o2.register_recipient(keys(&fresh));
    let p2 = o2.create_private(spec("size")).unwrap();
    o2.grant(
        p2,
        fresh.sign_key(),
        Uses::RETRIEVAL,
        LICENSE,
        T0 + DAY,
        vec![],
        T0,
    )
    .unwrap();
    o2.withdraw(p2, Uses::ALL, T0 + 1).unwrap();
    let n2 = o2.outbound_notices(T0 + 1).unwrap().pop().unwrap();
    assert_eq!(
        n2.bytes.len() - oh_share::codec::SEAL_HEADER_LEN - oh_share::codec::SEAL_TAG_LEN,
        227
    );
    assert_eq!(fresh.handle_notice(&n2.bytes, T0 + 2).unwrap().len(), 223);
}
