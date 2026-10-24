#![allow(dead_code)]

use beacon_core::Keypair;
use oh_share::codec::seal;
use oh_share::net::serve_notice_connection;
use oh_share::*;
use rand::rngs::OsRng;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use x25519_dalek::StaticSecret;

pub const T0: u64 = 1_800_000_000;
pub const DAY: u64 = 86_400;
pub const LICENSE: &str = "CC-BY-4.0";
pub const SECRET_TRACE: &str = "trace: step 1 loaded tile 7, step 2 fused add, outcome 3.2x";

pub fn env() -> Environment {
    Environment {
        abi: "omega-abi-1".into(),
        model: "tiny-byte-v0".into(),
        precision: "f32".into(),
        hardware: "cpu-aarch64".into(),
    }
}

pub fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        environment: env(),
        allowed_capabilities: Capabilities(
            Capabilities::DATA_READ.0 | Capabilities::REPRODUCE.0 | Capabilities::NATIVE_EXECUTE.0,
        ),
        accepted_licenses: vec![LICENSE.to_string()],
        max_clock_skew: 300,
    }
}

pub fn recipient_with(policy: ReceiverPolicy) -> Recipient {
    Recipient::new(
        Keypair::generate(),
        StaticSecret::random_from_rng(OsRng),
        policy,
    )
}

pub fn recipient() -> Recipient {
    recipient_with(policy())
}

/// A recipient whose signing key the test can reuse, to play a dishonest node.
pub fn recipient_seeded() -> (Recipient, [u8; 32]) {
    let seed: [u8; 32] = rand::random();
    let r = Recipient::new(
        Keypair::from_seed(&seed),
        StaticSecret::random_from_rng(OsRng),
        policy(),
    );
    (r, seed)
}

pub fn keys(r: &Recipient) -> RecipientKeys {
    RecipientKeys {
        sign_key: r.sign_key(),
        box_key: r.box_key(),
    }
}

pub fn payload(tag: &str) -> CapsulePayload {
    CapsulePayload {
        program: format!(
            "fn fused_add_{tag}(a: tensor<f32>, b: tensor<f32>) -> tensor<f32> {{ a + b }}"
        ),
        trace: SECRET_TRACE.to_string(),
        outcome: format!("verified speedup for {tag}"),
    }
}

pub fn spec(tag: &str) -> PackageSpec {
    PackageSpec {
        payload: payload(tag),
        environment: env(),
        capabilities: Capabilities(Capabilities::DATA_READ.0 | Capabilities::REPRODUCE.0),
        evidence: Evidence {
            tier: EvidenceTier::SelfReported,
            verifier: [0; 32],
            claim: "fused add is faster".into(),
        },
        parent: None,
        valid_for: 7 * DAY,
    }
}

/// An owner ledger plus a copy of its key so tests can forge or re-sign.
pub fn owner() -> (OwnerLedger, [u8; 32]) {
    let seed: [u8; 32] = rand::random();
    (OwnerLedger::new(Keypair::from_seed(&seed), 7 * DAY), seed)
}

/// Builds a capsule by hand, outside the owner ledger, so tests can make
/// capsules the ledger would never make. `pre` edits before signing,
/// `post` after.
pub fn hand_capsule(
    owner: &Keypair,
    to: &Recipient,
    pre: impl FnOnce(&mut OwnerConsent, &mut CapsuleHeader, &mut CapsulePayload),
    post: impl FnOnce(&mut CapsuleHeader, &mut CapsulePayload),
) -> Vec<u8> {
    let mut consent = OwnerConsent {
        version: 1,
        owner_id: owner.pubkey_bytes(),
        signer: [0; 32],
        package_id: rand::random(),
        recipient: to.sign_key(),
        uses: Uses(Uses::RETRIEVAL.0 | Uses::INDEX.0),
        license: LICENSE.into(),
        retention_end: T0 + 30 * DAY,
        custodians: vec![],
        issued_at: T0,
        seq: 0,
        sig: vec![],
    };
    let mut payload = payload("hand");
    let mut header = CapsuleHeader {
        version: 1,
        capsule_id: rand::random(),
        parent: None,
        consent: consent.clone(),
        content_digest: [0; 32],
        environment: env(),
        capabilities: Capabilities::DATA_READ,
        evidence: Evidence {
            tier: EvidenceTier::SelfReported,
            verifier: [0; 32],
            claim: "claim".into(),
        },
        created_at: T0,
        expires_at: T0 + 7 * DAY,
        revocation_head: 0,
        signer: [0; 32],
        sig: vec![],
    };
    pre(&mut consent, &mut header, &mut payload);
    if consent.sig.is_empty() {
        consent.sign_with(owner);
    }
    header.consent = consent;
    header.content_digest = payload.digest();
    if header.sig.is_empty() {
        header.sign_with(owner);
    }
    post(&mut header, &mut payload);
    seal(
        &to.box_key(),
        &Capsule { header, payload }.encode().unwrap(),
    )
    .unwrap()
}

/// A loopback recipient that answers `n` notice connections.
pub fn serve(recipient: Arc<Mutex<Recipient>>, n: usize, now: u64) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        for _ in 0..n {
            let (stream, _) = listener.accept().unwrap();
            let _ = serve_notice_connection(stream, &recipient, now);
        }
    });
    (addr, handle)
}

/// A loopback address with nothing listening: bind, read the port, close.
pub fn offline_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
