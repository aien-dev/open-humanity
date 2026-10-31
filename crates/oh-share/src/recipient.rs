//! The recipient's side: the capsule receiver, the revocation registry and
//! the use gates that consult it before serving, republishing, indexing or
//! training.
//!
//! The receiver trusts nothing a capsule says about itself. It re-checks the
//! signatures, the content digest, the consent, the license, staleness, the
//! revocation state, the declared environment against its own, and the
//! requested capabilities against its own policy. A capsule that passes is
//! accepted as data only: whether its claim reproduces, and whether a native
//! realization qualifies on this machine, stay `Untrusted` until the
//! receiver's own verifier says otherwise.

use crate::codec::{open, CodecError, MAX_CAPSULE_BYTES, MAX_CONTROL_BYTES};
use crate::consent::{
    Capabilities, Capsule, CapsuleHeader, CapsulePayload, Environment, EvidenceTier, Key,
    PackageId, UseAction, Uses, CAPSULE_VERSION, CONSENT_VERSION,
};
use crate::retraction::{
    AckOutcome, ErasureStatus, KeyRotation, NoticeRejectReason, RetractionAck, RetractionNotice,
    MAX_LISTED_CHECKPOINTS, RETRACTION_VERSION,
};
use beacon_core::{Keypair, PersonalDataFirewall};
use std::collections::{HashMap, HashSet};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// What this receiver accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverPolicy {
    /// This machine's exact environment.
    pub environment: Environment,
    /// Capabilities a capsule may ask for. External effects are refused
    /// even when listed here.
    pub allowed_capabilities: Capabilities,
    pub accepted_licenses: Vec<String>,
    /// Seconds a capsule's creation time may lie in the future.
    pub max_clock_skew: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapsuleRejection {
    #[error("envelope rejected: {0}")]
    Envelope(CodecError),
    #[error("capsule does not decode: {0}")]
    Malformed(String),
    #[error("unsupported capsule or consent version")]
    UnsupportedVersion,
    #[error("capsule is addressed to another recipient")]
    WrongRecipient,
    #[error("signed by an owner key a rotation retired")]
    StaleKey,
    #[error("signer is not the owner's current key")]
    UnauthorizedSigner,
    #[error("consent signature or signer is invalid")]
    ForgedConsent,
    #[error("capsule header signature does not verify")]
    BadSignature,
    #[error("payload does not match the signed content digest")]
    DigestMismatch,
    #[error("the owner withdrew this package")]
    Revoked,
    #[error("signed before an owner retraction this receiver already holds")]
    StaleRevocationHead,
    #[error("capsule expired")]
    Expired,
    #[error("capsule created in the future")]
    FromFuture,
    #[error("consent uses carry unknown bits")]
    UnknownUses,
    #[error("consent does not grant retrieval")]
    NoRetrievalConsent,
    #[error("consent expired")]
    ConsentExpired,
    #[error("license {0:?} is not accepted here")]
    UnknownLicense(String),
    #[error("environment field {0} does not match this machine")]
    IncompatibleEnvironment(&'static str),
    #[error("capsule requests unknown capability bits")]
    UnknownCapability,
    #[error("capsule requests an external effect")]
    ForbiddenCapability,
    #[error("capsule requests capabilities outside this receiver's policy")]
    CapabilityOutOfScope,
    #[error("payload failed the personal data firewall: {0}")]
    Firewall(String),
    #[error("capsule already received")]
    Duplicate,
    #[error("a different consent for this package is already held; package quarantined")]
    ContradictoryConsent,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UseDenied {
    #[error("the owner withdrew this use")]
    Revoked,
    #[error("package not held")]
    NotHeld,
    #[error("package quarantined after contradictory consent")]
    Quarantined,
    #[error("consent expired")]
    ConsentExpired,
    #[error("the owner never granted this use")]
    NotConsented,
    #[error("capability not allowed by capsule and policy")]
    CapabilityNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationError {
    #[error("rotation envelope or encoding rejected: {0}")]
    Codec(CodecError),
    #[error("rotation signatures do not verify")]
    BadSignature,
    #[error("old key is not the owner's current key")]
    NotCurrent,
    #[error("rotation sequence is not newer")]
    Replay,
    #[error("unsupported version")]
    UnsupportedVersion,
}

/// One qualification stage. Only the receiver's own verifier moves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Untrusted,
    Passed { verifier: String },
    Failed { verifier: String },
}

/// The three separate states of an accepted capsule. Stage one never
/// implies stage two or three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qualification {
    pub data_accepted: bool,
    pub claim_reproduced: Stage,
    pub native_qualified: Stage,
}

/// What a checkpoint trained on a later-withdrawn package is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointStatus {
    Clean,
    /// Quarantined. Its weights are not verifiably free of the package;
    /// the only honest options are a rebuild without it or retirement.
    Quarantined {
        erasure: ErasureStatus,
    },
}

/// Metadata-only index entry. Never carries the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub owner_id: Key,
    pub package_id: PackageId,
    pub capsule_id: [u8; 16],
    pub parent: Option<[u8; 16]>,
    pub environment: Environment,
    pub evidence_tier: EvidenceTier,
}

/// A tombstone a stateless peer can carry: ids and scope only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    pub owner_id: Key,
    pub package_id: PackageId,
    pub scope: Uses,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub owner_id: Key,
    pub package_id: PackageId,
    pub capsule_id: [u8; 16],
}

struct OwnerState {
    current_key: Key,
    retired: HashSet<Key>,
    rotation_seq: u64,
    retraction_head: u64,
}

struct Held {
    header: CapsuleHeader,
    payload: CapsulePayload,
    qualification: Qualification,
    quarantined: bool,
}

struct TrainingRecord {
    owner_id: Key,
    package_id: PackageId,
    checkpoint: [u8; 16],
    quarantined: bool,
}

/// A participating recipient node.
pub struct Recipient {
    identity: Keypair,
    box_secret: StaticSecret,
    policy: ReceiverPolicy,
    owners: HashMap<Key, OwnerState>,
    held: HashMap<(Key, PackageId), Held>,
    tombstones: HashMap<(Key, PackageId), Tombstone>,
    seen_headers: HashSet<[u8; 32]>,
    seen_capsule_ids: HashSet<(Key, [u8; 16])>,
    acks: HashMap<[u8; 32], Vec<u8>>,
    training: Vec<TrainingRecord>,
}

fn env_mismatch(theirs: &Environment, ours: &Environment) -> Option<&'static str> {
    if theirs.abi != ours.abi {
        Some("abi")
    } else if theirs.model != ours.model {
        Some("model")
    } else if theirs.precision != ours.precision {
        Some("precision")
    } else if theirs.hardware != ours.hardware {
        Some("hardware")
    } else {
        None
    }
}

impl Recipient {
    pub fn new(identity: Keypair, box_secret: StaticSecret, policy: ReceiverPolicy) -> Self {
        Self {
            identity,
            box_secret,
            policy,
            owners: HashMap::new(),
            held: HashMap::new(),
            tombstones: HashMap::new(),
            seen_headers: HashSet::new(),
            seen_capsule_ids: HashSet::new(),
            acks: HashMap::new(),
            training: Vec::new(),
        }
    }

    pub fn sign_key(&self) -> Key {
        self.identity.pubkey_bytes()
    }

    pub fn box_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.box_secret).to_bytes()
    }

    /// The key that may currently sign for `owner_id`: the latest rotated
    /// key, or the genesis key itself for an owner never seen rotating.
    fn current_key(&self, owner_id: &Key) -> Key {
        self.owners
            .get(owner_id)
            .map(|s| s.current_key)
            .unwrap_or(*owner_id)
    }

    fn is_retired(&self, owner_id: &Key, key: &Key) -> bool {
        self.owners
            .get(owner_id)
            .is_some_and(|s| s.retired.contains(key))
    }

    fn owner_state(&mut self, owner_id: Key) -> &mut OwnerState {
        self.owners.entry(owner_id).or_insert_with(|| OwnerState {
            current_key: owner_id,
            retired: HashSet::new(),
            rotation_seq: 0,
            retraction_head: 0,
        })
    }

    /// Opens, checks and stores one capsule as untrusted data.
    pub fn receive_capsule(
        &mut self,
        envelope: &[u8],
        now: u64,
    ) -> Result<Accepted, CapsuleRejection> {
        let plain = open(&self.box_secret, envelope, MAX_CAPSULE_BYTES)
            .map_err(CapsuleRejection::Envelope)?;
        let capsule: Capsule = crate::codec::decode(&plain, MAX_CAPSULE_BYTES)
            .map_err(|e| CapsuleRejection::Malformed(e.to_string()))?;
        let Capsule { header, payload } = capsule;
        let consent = &header.consent;
        let owner_id = consent.owner_id;
        let package_id = consent.package_id;

        if header.version != CAPSULE_VERSION || consent.version != CONSENT_VERSION {
            return Err(CapsuleRejection::UnsupportedVersion);
        }
        if consent.recipient != self.sign_key() {
            return Err(CapsuleRejection::WrongRecipient);
        }
        // Authority: only the owner's current key grants. Custodians may
        // withdraw but never grant, so they are not consulted here.
        let current = self.current_key(&owner_id);
        if self.is_retired(&owner_id, &header.signer) || self.is_retired(&owner_id, &consent.signer)
        {
            return Err(CapsuleRejection::StaleKey);
        }
        if header.signer != current {
            return Err(CapsuleRejection::UnauthorizedSigner);
        }
        if consent.signer != current || !consent.signature_valid() {
            return Err(CapsuleRejection::ForgedConsent);
        }
        if !header.signature_valid() {
            return Err(CapsuleRejection::BadSignature);
        }
        if payload.digest() != header.content_digest {
            return Err(CapsuleRejection::DigestMismatch);
        }
        if self.tombstones.contains_key(&(owner_id, package_id)) {
            return Err(CapsuleRejection::Revoked);
        }
        let head = self.owners.get(&owner_id).map_or(0, |s| s.retraction_head);
        if header.revocation_head < head {
            return Err(CapsuleRejection::StaleRevocationHead);
        }
        if now > header.expires_at {
            return Err(CapsuleRejection::Expired);
        }
        if header.created_at > now.saturating_add(self.policy.max_clock_skew) {
            return Err(CapsuleRejection::FromFuture);
        }
        if !consent.uses.is_known() {
            return Err(CapsuleRejection::UnknownUses);
        }
        if !consent.uses.contains(Uses::RETRIEVAL) {
            return Err(CapsuleRejection::NoRetrievalConsent);
        }
        if consent.retention_end <= now {
            return Err(CapsuleRejection::ConsentExpired);
        }
        if !self.policy.accepted_licenses.contains(&consent.license) {
            return Err(CapsuleRejection::UnknownLicense(consent.license.clone()));
        }
        if let Some(field) = env_mismatch(&header.environment, &self.policy.environment) {
            return Err(CapsuleRejection::IncompatibleEnvironment(field));
        }
        let caps = header.capabilities;
        if !Capabilities::KNOWN.contains(caps) {
            return Err(CapsuleRejection::UnknownCapability);
        }
        if caps.intersects(Capabilities::EXTERNAL_EFFECTS) {
            return Err(CapsuleRejection::ForbiddenCapability);
        }
        if !self.policy.allowed_capabilities.contains(caps) {
            return Err(CapsuleRejection::CapabilityOutOfScope);
        }
        for text in payload.texts() {
            PersonalDataFirewall::verify_clean(text)
                .map_err(|v| CapsuleRejection::Firewall(v.to_string()))?;
        }
        let header_digest = header.digest();
        if self.seen_headers.contains(&header_digest)
            || self
                .seen_capsule_ids
                .contains(&(owner_id, header.capsule_id))
        {
            return Err(CapsuleRejection::Duplicate);
        }
        if let Some(existing) = self.held.get_mut(&(owner_id, package_id)) {
            if !existing.header.consent.same_terms(consent) {
                existing.quarantined = true;
                return Err(CapsuleRejection::ContradictoryConsent);
            }
            return Err(CapsuleRejection::Duplicate);
        }

        self.seen_headers.insert(header_digest);
        self.seen_capsule_ids.insert((owner_id, header.capsule_id));
        let accepted = Accepted {
            owner_id,
            package_id,
            capsule_id: header.capsule_id,
        };
        self.owner_state(owner_id);
        self.held.insert(
            (owner_id, package_id),
            Held {
                header,
                payload,
                qualification: Qualification {
                    data_accepted: true,
                    claim_reproduced: Stage::Untrusted,
                    native_qualified: Stage::Untrusted,
                },
                quarantined: false,
            },
        );
        Ok(accepted)
    }

    /// Applies an owner key rotation signed by both keys.
    pub fn handle_rotation(&mut self, envelope: &[u8]) -> Result<(), RotationError> {
        let plain =
            open(&self.box_secret, envelope, MAX_CONTROL_BYTES).map_err(RotationError::Codec)?;
        let rotation = KeyRotation::from_bytes(&plain).map_err(RotationError::Codec)?;
        if rotation.version != RETRACTION_VERSION {
            return Err(RotationError::UnsupportedVersion);
        }
        if !rotation.signatures_valid() {
            return Err(RotationError::BadSignature);
        }
        let applied = self
            .owners
            .get(&rotation.owner_id)
            .map_or(0, |s| s.rotation_seq);
        if rotation.seq <= applied {
            return Err(RotationError::Replay);
        }
        if rotation.old_key != self.current_key(&rotation.owner_id) {
            return Err(RotationError::NotCurrent);
        }
        let state = self.owner_state(rotation.owner_id);
        state.retired.insert(rotation.old_key);
        state.current_key = rotation.new_key;
        state.rotation_seq = rotation.seq;
        Ok(())
    }

    fn notice_authority(&self, notice: &RetractionNotice) -> Result<(), NoticeRejectReason> {
        if self.is_retired(&notice.owner_id, &notice.signer) {
            return Err(NoticeRejectReason::StaleKey);
        }
        if notice.signer == self.current_key(&notice.owner_id) {
            return Ok(());
        }
        let custodian = self
            .held
            .get(&(notice.owner_id, notice.package_id))
            .is_some_and(|h| h.header.consent.custodians.contains(&notice.signer));
        if custodian {
            Ok(())
        } else {
            Err(NoticeRejectReason::UnauthorizedSigner)
        }
    }

    fn sign_ack(
        &self,
        notice: &RetractionNotice,
        outcome: AckOutcome,
        influenced: Vec<[u8; 16]>,
        now: u64,
    ) -> Vec<u8> {
        let mut listed = influenced;
        listed.sort_unstable();
        listed.dedup();
        let influenced_total = listed.len() as u64;
        listed.truncate(MAX_LISTED_CHECKPOINTS);
        let mut ack = RetractionAck {
            version: RETRACTION_VERSION,
            notice_digest: notice.digest(),
            owner_id: notice.owner_id,
            package_id: notice.package_id,
            seq: notice.seq,
            recipient: [0; 32],
            outcome,
            influenced_checkpoints: listed,
            influenced_total,
            acked_at: now,
            sig: Vec::new(),
        };
        ack.sign_with(&self.identity);
        ack.to_bytes().expect("ack fits the control limit")
    }

    /// Handles one sealed retraction notice. The tombstone is recorded
    /// before the ack is signed, so an ack is never ahead of enforcement.
    /// Returns the signed ack, or `None` when the envelope cannot be opened
    /// or decoded (there is no authenticated sender to answer). A repeated
    /// notice gets the same ack again and changes nothing. A valid notice
    /// for a package not held yet is enforced too, so a withdrawal that
    /// overtakes its capsule still wins. Tombstones hold ids only; their
    /// count is not yet capped per owner (a key can only tombstone its own
    /// packages, but can add many).
    pub fn handle_notice(&mut self, envelope: &[u8], now: u64) -> Option<Vec<u8>> {
        let plain = open(&self.box_secret, envelope, MAX_CONTROL_BYTES).ok()?;
        let notice = RetractionNotice::from_bytes(&plain).ok()?;
        let digest = notice.digest();
        if let Some(ack) = self.acks.get(&digest) {
            return Some(ack.clone());
        }
        let reject = |me: &Self, reason| {
            Some(me.sign_ack(&notice, AckOutcome::Rejected(reason), Vec::new(), now))
        };
        if notice.version != RETRACTION_VERSION {
            return reject(self, NoticeRejectReason::UnsupportedVersion);
        }
        if notice.recipient != self.sign_key() {
            return reject(self, NoticeRejectReason::WrongRecipient);
        }
        if let Err(reason) = self.notice_authority(&notice) {
            return reject(self, reason);
        }
        if !notice.signature_valid() {
            return reject(self, NoticeRejectReason::BadSignature);
        }
        if !notice.scope.is_known() || notice.scope == Uses::NONE {
            return reject(self, NoticeRejectReason::UnknownScope);
        }

        // Enforce first. Withdrawal only ever widens.
        let key = (notice.owner_id, notice.package_id);
        let tomb = self.tombstones.entry(key).or_insert(Tombstone {
            owner_id: notice.owner_id,
            package_id: notice.package_id,
            scope: Uses::NONE,
            seq: 0,
        });
        tomb.scope = tomb.scope.union(notice.scope);
        tomb.seq = tomb.seq.max(notice.seq);
        let state = self.owner_state(notice.owner_id);
        state.retraction_head = state.retraction_head.max(notice.seq);
        let mut influenced = Vec::new();
        for record in &mut self.training {
            if record.owner_id == notice.owner_id && record.package_id == notice.package_id {
                record.quarantined = true;
                influenced.push(record.checkpoint);
            }
        }
        let ack = self.sign_ack(
            &notice,
            AckOutcome::FutureUseBlocked {
                scope: notice.scope,
            },
            influenced,
            now,
        );
        self.acks.insert(digest, ack.clone());
        Some(ack)
    }

    /// The gate every use passes through.
    pub fn authorize(
        &self,
        owner_id: Key,
        package_id: PackageId,
        action: UseAction,
        now: u64,
    ) -> Result<(), UseDenied> {
        let required = action.required();
        if self
            .tombstones
            .get(&(owner_id, package_id))
            .is_some_and(|t| t.scope.contains(required))
        {
            return Err(UseDenied::Revoked);
        }
        let held = self
            .held
            .get(&(owner_id, package_id))
            .ok_or(UseDenied::NotHeld)?;
        if held.quarantined {
            return Err(UseDenied::Quarantined);
        }
        let consent = &held.header.consent;
        if consent.retention_end <= now {
            return Err(UseDenied::ConsentExpired);
        }
        if !consent.uses.contains(required) {
            return Err(UseDenied::NotConsented);
        }
        Ok(())
    }

    /// Serves the payload back, if the gate allows retrieval.
    pub fn serve(
        &self,
        owner_id: Key,
        package_id: PackageId,
        now: u64,
    ) -> Result<&CapsulePayload, UseDenied> {
        self.authorize(owner_id, package_id, UseAction::Serve, now)?;
        Ok(&self.held[&(owner_id, package_id)].payload)
    }

    /// Metadata-only index entry, if the gate allows indexing.
    pub fn index_entry(
        &self,
        owner_id: Key,
        package_id: PackageId,
        now: u64,
    ) -> Result<IndexEntry, UseDenied> {
        self.authorize(owner_id, package_id, UseAction::Index, now)?;
        let header = &self.held[&(owner_id, package_id)].header;
        Ok(IndexEntry {
            owner_id,
            package_id,
            capsule_id: header.capsule_id,
            parent: header.parent,
            environment: header.environment.clone(),
            evidence_tier: header.evidence.tier,
        })
    }

    /// Records that `checkpoint` (an aien-train provenance id) is about to
    /// train on the package, if the gate allows training.
    pub fn begin_training(
        &mut self,
        owner_id: Key,
        package_id: PackageId,
        checkpoint: [u8; 16],
        now: u64,
    ) -> Result<(), UseDenied> {
        self.authorize(owner_id, package_id, UseAction::Train, now)?;
        self.training.push(TrainingRecord {
            owner_id,
            package_id,
            checkpoint,
            quarantined: false,
        });
        Ok(())
    }

    /// Status of one checkpoint; `None` when it never trained on any shared
    /// package here.
    pub fn checkpoint_status(&self, checkpoint: [u8; 16]) -> Option<CheckpointStatus> {
        let mut records = self
            .training
            .iter()
            .filter(|r| r.checkpoint == checkpoint)
            .peekable();
        records.peek()?;
        if records.any(|r| r.quarantined) {
            Some(CheckpointStatus::Quarantined {
                erasure: ErasureStatus::NotVerifiablyErased,
            })
        } else {
            Some(CheckpointStatus::Clean)
        }
    }

    pub fn qualification(&self, owner_id: Key, package_id: PackageId) -> Option<Qualification> {
        self.held
            .get(&(owner_id, package_id))
            .map(|h| h.qualification.clone())
    }

    fn stage_allowed(
        &self,
        owner_id: Key,
        package_id: PackageId,
        capability: Capabilities,
        now: u64,
    ) -> Result<(), UseDenied> {
        self.authorize(owner_id, package_id, UseAction::Serve, now)?;
        let caps = self.held[&(owner_id, package_id)].header.capabilities;
        if !caps.contains(capability) || !self.policy.allowed_capabilities.contains(capability) {
            return Err(UseDenied::CapabilityNotAllowed);
        }
        Ok(())
    }

    /// Records the result of this receiver's own reproduction of the claim.
    pub fn record_reproduction(
        &mut self,
        owner_id: Key,
        package_id: PackageId,
        passed: bool,
        verifier: &str,
        now: u64,
    ) -> Result<(), UseDenied> {
        self.stage_allowed(owner_id, package_id, Capabilities::REPRODUCE, now)?;
        let verifier = verifier.to_string();
        let held = self.held.get_mut(&(owner_id, package_id)).expect("checked");
        held.qualification.claim_reproduced = if passed {
            Stage::Passed { verifier }
        } else {
            Stage::Failed { verifier }
        };
        Ok(())
    }

    /// Records the result of this receiver's own native qualification on
    /// its own hardware.
    pub fn record_native_qualification(
        &mut self,
        owner_id: Key,
        package_id: PackageId,
        passed: bool,
        verifier: &str,
        now: u64,
    ) -> Result<(), UseDenied> {
        self.stage_allowed(owner_id, package_id, Capabilities::NATIVE_EXECUTE, now)?;
        let verifier = verifier.to_string();
        let held = self.held.get_mut(&(owner_id, package_id)).expect("checked");
        held.qualification.native_qualified = if passed {
            Stage::Passed { verifier }
        } else {
            Stage::Failed { verifier }
        };
        Ok(())
    }

    /// Every tombstone this node holds: ids and scope, no content.
    pub fn tombstones(&self) -> Vec<Tombstone> {
        self.tombstones.values().cloned().collect()
    }
}
