//! The owner's side: private by default, explicit single-package publish to
//! one registered recipient, local withdrawal that works offline, and
//! per-recipient acknowledgement tracking.
//!
//! Every method takes `&mut self`; wrap the ledger in a `Mutex` to share it.
//! Withdrawal and publication then serialize on that lock, so once
//! `withdraw` returns, no later `publish` for the package can succeed.

use crate::codec::{seal, CodecError, MAX_CAPSULE_BYTES};
use crate::consent::{
    Capabilities, Capsule, CapsuleHeader, CapsulePayload, Environment, Evidence, Key, OwnerConsent,
    PackageId, Uses, CAPSULE_VERSION, CONSENT_VERSION,
};
use crate::retraction::{
    AckOutcome, ErasureStatus, KeyRotation, NoticeRejectReason, RetractionAck, RetractionNotice,
    RETRACTION_VERSION,
};
use beacon_core::{Keypair, PersonalDataFirewall};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};

/// A recipient the owner has chosen to permit: its signing key and the
/// X25519 key that capsules and notices are sealed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientKeys {
    pub sign_key: Key,
    pub box_key: [u8; 32],
}

/// What the owner wants to share, before any grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    pub payload: CapsulePayload,
    pub environment: Environment,
    pub capabilities: Capabilities,
    pub evidence: Evidence,
    pub parent: Option<[u8; 16]>,
    /// Seconds a built capsule stays fresh.
    pub valid_for: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageState {
    /// Never sent anywhere. The default.
    Private,
    /// Sent to at least one recipient.
    Published,
    /// Withdrawn. No new send is possible, whatever the scope.
    Withdrawn { seq: u64, at: u64, scope: Uses },
}

/// Delivery state of one retraction notice to one recipient. Only a
/// verified signed ack moves it to `Acknowledged` or `Rejected`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Not yet acknowledged; still inside the retry window.
    Pending { attempts: u32 },
    /// The recipient signed that it now refuses every use in `scope`.
    Acknowledged { at: u64, scope: Uses },
    /// The recipient signed a refusal; the package may still be in use there.
    Rejected { reason: NoticeRejectReason },
    /// The retry window closed without an ack. The recipient may still be
    /// serving the package.
    Unreachable { attempts: u32, since: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnerError {
    #[error("no such package")]
    UnknownPackage,
    #[error("recipient is not registered")]
    UnregisteredRecipient,
    #[error("no grant for this recipient")]
    NotGranted,
    #[error("package was withdrawn; no new share, index or training is possible")]
    Withdrawn,
    #[error("consent expired")]
    ConsentExpired,
    #[error("uses carry unknown bits or grant nothing")]
    BadUses,
    #[error("a grant with different terms already exists; withdraw and share a new package")]
    ConflictingGrant,
    #[error("payload failed the personal data firewall: {0}")]
    Firewall(String),
    #[error("encoding failed: {0}")]
    Codec(#[from] CodecError),
    #[error("no delivery to this recipient for this package")]
    NoDelivery,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AckError {
    #[error("ack does not decode")]
    Malformed,
    #[error("ack names no outstanding notice")]
    UnknownNotice,
    #[error("ack signature does not verify under the registered recipient key")]
    BadSignature,
    #[error("ack fields do not match the notice")]
    Mismatch,
    #[error("ack scope is narrower than the notice scope")]
    ScopeShort,
}

/// A sealed capsule ready to hand to the transport, with the logical event
/// number at which the gate admitted it.
#[derive(Debug, Clone)]
pub struct SealedCapsule {
    pub recipient: Key,
    pub package_id: PackageId,
    pub event: u64,
    pub bytes: Vec<u8>,
}

/// A sealed notice for one recipient.
#[derive(Debug, Clone)]
pub struct OutboundNotice {
    pub recipient: Key,
    pub package_id: PackageId,
    pub notice_digest: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Minimal record of a withdrawal: ids, scope and recipients only. It holds
/// neither the withdrawn text nor its content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalReceipt {
    pub package_id: PackageId,
    pub seq: u64,
    pub at: u64,
    pub scope: Uses,
    pub recipients: Vec<Key>,
    pub event: u64,
}

/// One recipient's grant and retraction status, as the owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientView {
    pub recipient: Key,
    pub uses: Uses,
    pub training_consent: bool,
    pub license: String,
    pub retention_end: u64,
    pub received: bool,
    pub retraction: Option<DeliveryStatus>,
    /// Checkpoint ids the recipient listed (at most `MAX_LISTED_CHECKPOINTS`).
    pub influenced_checkpoints: Vec<[u8; 16]>,
    /// Total distinct checkpoints the recipient reported.
    pub influenced_total: u64,
}

/// Everything the owner has shared for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageView {
    pub package_id: PackageId,
    pub state: PackageState,
    /// False once withdrawn: the ledger keeps no withdrawn text.
    pub payload_retained: bool,
    pub recipients: Vec<RecipientView>,
    /// Copies outside participating nodes, once anything was sent.
    pub uncontrolled_copies: Option<ErasureStatus>,
    /// Weights trained, or possibly trained, on the package.
    pub trained_weights: Option<ErasureStatus>,
}

struct Delivery {
    notice: RetractionNotice,
    status: DeliveryStatus,
    influenced_checkpoints: Vec<[u8; 16]>,
    influenced_total: u64,
}

struct PackageRecord {
    state: PackageState,
    payload: Option<CapsulePayload>,
    environment: Environment,
    capabilities: Capabilities,
    evidence: Evidence,
    parent: Option<[u8; 16]>,
    valid_for: u64,
    grants: BTreeMap<Key, OwnerConsent>,
    sent_to: BTreeSet<Key>,
    deliveries: BTreeMap<Key, Delivery>,
    receipt: Option<WithdrawalReceipt>,
}

/// The owner's sharing ledger.
pub struct OwnerLedger {
    keypair: Keypair,
    owner_id: Key,
    seq: u64,
    retraction_head: u64,
    retry_window: u64,
    event: u64,
    recipients: BTreeMap<Key, RecipientKeys>,
    packages: BTreeMap<PackageId, PackageRecord>,
    rotation: Option<KeyRotation>,
}

fn random_16() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

impl OwnerLedger {
    /// `retry_window` is how many seconds a retraction notice is retried
    /// before its recipient is reported unreachable.
    pub fn new(keypair: Keypair, retry_window: u64) -> Self {
        let owner_id = keypair.pubkey_bytes();
        Self {
            keypair,
            owner_id,
            seq: 0,
            retraction_head: 0,
            retry_window,
            event: 0,
            recipients: BTreeMap::new(),
            packages: BTreeMap::new(),
            rotation: None,
        }
    }

    pub fn owner_id(&self) -> Key {
        self.owner_id
    }

    pub fn current_key(&self) -> Key {
        self.keypair.pubkey_bytes()
    }

    fn next_event(&mut self) -> u64 {
        self.event += 1;
        self.event
    }

    /// Permits a recipient. Nothing is ever sent to an unregistered key.
    pub fn register_recipient(&mut self, keys: RecipientKeys) {
        self.recipients.insert(keys.sign_key, keys);
    }

    /// Records a package as private. Nothing is sent. The payload must pass
    /// the personal data firewall and fit one capsule.
    pub fn create_private(&mut self, spec: PackageSpec) -> Result<PackageId, OwnerError> {
        for text in spec.payload.texts() {
            PersonalDataFirewall::verify_clean(text)
                .map_err(|v| OwnerError::Firewall(v.to_string()))?;
        }
        crate::codec::encode(&spec.payload, MAX_CAPSULE_BYTES / 2)?;
        let package_id = random_16();
        self.packages.insert(
            package_id,
            PackageRecord {
                state: PackageState::Private,
                payload: Some(spec.payload),
                environment: spec.environment,
                capabilities: spec.capabilities,
                evidence: spec.evidence,
                parent: spec.parent,
                valid_for: spec.valid_for,
                grants: BTreeMap::new(),
                sent_to: BTreeSet::new(),
                deliveries: BTreeMap::new(),
                receipt: None,
            },
        );
        Ok(package_id)
    }

    /// Grants `uses` of one package to one registered recipient. Training is
    /// granted only when `uses` names `Uses::TRAINING` explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &mut self,
        package_id: PackageId,
        recipient: Key,
        uses: Uses,
        license: &str,
        retention_end: u64,
        custodians: Vec<Key>,
        now: u64,
    ) -> Result<OwnerConsent, OwnerError> {
        if !uses.is_known() || uses == Uses::NONE {
            return Err(OwnerError::BadUses);
        }
        if !self.recipients.contains_key(&recipient) {
            return Err(OwnerError::UnregisteredRecipient);
        }
        let owner_id = self.owner_id;
        let seq = self.seq;
        let record = self
            .packages
            .get_mut(&package_id)
            .ok_or(OwnerError::UnknownPackage)?;
        if matches!(record.state, PackageState::Withdrawn { .. }) {
            return Err(OwnerError::Withdrawn);
        }
        let mut consent = OwnerConsent {
            version: CONSENT_VERSION,
            owner_id,
            signer: [0; 32],
            package_id,
            recipient,
            uses,
            license: license.to_string(),
            retention_end,
            custodians,
            issued_at: now,
            seq,
            sig: Vec::new(),
        };
        consent.sign_with(&self.keypair);
        consent.to_bytes()?;
        if let Some(existing) = record.grants.get(&recipient) {
            if !existing.same_terms(&consent) {
                return Err(OwnerError::ConflictingGrant);
            }
            return Ok(existing.clone());
        }
        record.grants.insert(recipient, consent.clone());
        Ok(consent)
    }

    /// Explicit single-package publish: builds, signs and seals one capsule
    /// for one granted recipient. Refused after withdrawal or expiry.
    pub fn publish(
        &mut self,
        package_id: PackageId,
        recipient: Key,
        now: u64,
    ) -> Result<SealedCapsule, OwnerError> {
        let keys = *self
            .recipients
            .get(&recipient)
            .ok_or(OwnerError::UnregisteredRecipient)?;
        let revocation_head = self.retraction_head;
        let record = self
            .packages
            .get(&package_id)
            .ok_or(OwnerError::UnknownPackage)?;
        if matches!(record.state, PackageState::Withdrawn { .. }) {
            return Err(OwnerError::Withdrawn);
        }
        let consent = record
            .grants
            .get(&recipient)
            .ok_or(OwnerError::NotGranted)?
            .clone();
        if consent.retention_end <= now {
            return Err(OwnerError::ConsentExpired);
        }
        let payload = record.payload.clone().ok_or(OwnerError::Withdrawn)?;
        let mut header = CapsuleHeader {
            version: CAPSULE_VERSION,
            capsule_id: random_16(),
            parent: record.parent,
            content_digest: payload.digest(),
            environment: record.environment.clone(),
            capabilities: record.capabilities,
            evidence: record.evidence.clone(),
            created_at: now,
            expires_at: now
                .saturating_add(record.valid_for)
                .min(consent.retention_end),
            revocation_head,
            consent,
            signer: [0; 32],
            sig: Vec::new(),
        };
        header.sign_with(&self.keypair);
        let bytes = seal(&keys.box_key, &Capsule { header, payload }.encode()?)?;
        let event = self.next_event();
        let record = self.packages.get_mut(&package_id).expect("checked above");
        record.state = PackageState::Published;
        record.sent_to.insert(recipient);
        Ok(SealedCapsule {
            recipient,
            package_id,
            event,
            bytes,
        })
    }

    /// Withdraws `scope` of one package. Works offline: the local gate
    /// closes at once, the withdrawn text is dropped from this ledger, and
    /// one signed notice per permitted recipient is queued as pending.
    /// Withdrawing again with a wider scope issues fresh notices.
    pub fn withdraw(
        &mut self,
        package_id: PackageId,
        scope: Uses,
        now: u64,
    ) -> Result<WithdrawalReceipt, OwnerError> {
        if !scope.is_known() || scope == Uses::NONE {
            return Err(OwnerError::BadUses);
        }
        let record = self
            .packages
            .get(&package_id)
            .ok_or(OwnerError::UnknownPackage)?;
        let previous = match record.state {
            PackageState::Withdrawn { scope: prev, .. } => {
                if prev.contains(scope) {
                    return Ok(record.receipt.clone().expect("withdrawn has receipt"));
                }
                prev
            }
            _ => Uses::NONE,
        };
        let scope = previous.union(scope);
        self.seq += 1;
        self.retraction_head = self.seq;
        let seq = self.seq;
        let event = self.next_event();
        let owner_id = self.owner_id;
        let retry_until = now.saturating_add(self.retry_window);
        let record = self.packages.get_mut(&package_id).expect("checked above");
        record.state = PackageState::Withdrawn {
            seq,
            at: now,
            scope,
        };
        record.payload = None;
        let recipients: Vec<Key> = record
            .grants
            .keys()
            .chain(record.sent_to.iter())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for recipient in &recipients {
            let mut notice = RetractionNotice {
                version: RETRACTION_VERSION,
                notice_id: random_16(),
                owner_id,
                signer: [0; 32],
                recipient: *recipient,
                package_id,
                scope,
                seq,
                issued_at: now,
                retry_until,
                sig: Vec::new(),
            };
            notice.sign_with(&self.keypair);
            let (influenced, influenced_total) = record
                .deliveries
                .get(recipient)
                .map(|d| (d.influenced_checkpoints.clone(), d.influenced_total))
                .unwrap_or_default();
            record.deliveries.insert(
                *recipient,
                Delivery {
                    notice,
                    status: DeliveryStatus::Pending { attempts: 0 },
                    influenced_checkpoints: influenced,
                    influenced_total,
                },
            );
        }
        let receipt = WithdrawalReceipt {
            package_id,
            seq,
            at: now,
            scope,
            recipients,
            event,
        };
        record.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Notices still pending inside their retry window, sealed for their
    /// recipients. Only registered recipients with a grant ever appear.
    /// Moves pending deliveries whose window closed to `Unreachable`.
    pub fn outbound_notices(&mut self, now: u64) -> Result<Vec<OutboundNotice>, OwnerError> {
        self.expire(now);
        let mut out = Vec::new();
        for (package_id, record) in &self.packages {
            for (recipient, delivery) in &record.deliveries {
                if !matches!(delivery.status, DeliveryStatus::Pending { .. }) {
                    continue;
                }
                let keys = self
                    .recipients
                    .get(recipient)
                    .ok_or(OwnerError::UnregisteredRecipient)?;
                out.push(OutboundNotice {
                    recipient: *recipient,
                    package_id: *package_id,
                    notice_digest: delivery.notice.digest(),
                    bytes: seal(&keys.box_key, &delivery.notice.to_bytes()?)?,
                });
            }
        }
        Ok(out)
    }

    /// Moves every pending delivery whose retry window closed to
    /// `Unreachable`.
    pub fn expire(&mut self, now: u64) {
        for record in self.packages.values_mut() {
            for delivery in record.deliveries.values_mut() {
                if let DeliveryStatus::Pending { attempts } = delivery.status {
                    if now > delivery.notice.retry_until {
                        delivery.status = DeliveryStatus::Unreachable {
                            attempts,
                            since: now,
                        };
                    }
                }
            }
        }
    }

    /// Records one failed delivery attempt (offline, no answer, or an
    /// answer that was not a valid ack).
    pub fn record_attempt_failed(
        &mut self,
        package_id: PackageId,
        recipient: Key,
        now: u64,
    ) -> Result<(), OwnerError> {
        let delivery = self
            .packages
            .get_mut(&package_id)
            .ok_or(OwnerError::UnknownPackage)?
            .deliveries
            .get_mut(&recipient)
            .ok_or(OwnerError::NoDelivery)?;
        if let DeliveryStatus::Pending { attempts } = delivery.status {
            delivery.status = DeliveryStatus::Pending {
                attempts: attempts + 1,
            };
        }
        self.expire(now);
        Ok(())
    }

    /// Re-signs a fresh notice for a recipient that went unreachable or
    /// rejected, opening a new retry window.
    pub fn reissue(
        &mut self,
        package_id: PackageId,
        recipient: Key,
        now: u64,
    ) -> Result<(), OwnerError> {
        let seq = self.seq + 1;
        let retry_until = now.saturating_add(self.retry_window);
        let keypair = &self.keypair;
        let delivery = self
            .packages
            .get_mut(&package_id)
            .ok_or(OwnerError::UnknownPackage)?
            .deliveries
            .get_mut(&recipient)
            .ok_or(OwnerError::NoDelivery)?;
        if matches!(delivery.status, DeliveryStatus::Acknowledged { .. }) {
            return Ok(());
        }
        let notice = &mut delivery.notice;
        notice.notice_id = random_16();
        notice.seq = seq;
        notice.issued_at = now;
        notice.retry_until = retry_until;
        notice.sign_with(keypair);
        delivery.status = DeliveryStatus::Pending { attempts: 0 };
        self.seq = seq;
        self.retraction_head = seq;
        Ok(())
    }

    /// Verifies a recipient's ack against the outstanding notice and the
    /// registered recipient key. A forged, mismatched or replayed-for-another
    /// notice ack changes nothing.
    pub fn record_ack(&mut self, bytes: &[u8], now: u64) -> Result<DeliveryStatus, AckError> {
        let ack = RetractionAck::from_bytes(bytes).map_err(|_| AckError::Malformed)?;
        let keys = self
            .recipients
            .get(&ack.recipient)
            .ok_or(AckError::UnknownNotice)?;
        let delivery = self
            .packages
            .get_mut(&ack.package_id)
            .ok_or(AckError::UnknownNotice)?
            .deliveries
            .get_mut(&ack.recipient)
            .ok_or(AckError::UnknownNotice)?;
        if delivery.notice.digest() != ack.notice_digest {
            return Err(AckError::UnknownNotice);
        }
        if ack.recipient != keys.sign_key || !ack.signature_valid() {
            return Err(AckError::BadSignature);
        }
        if ack.owner_id != delivery.notice.owner_id
            || ack.seq != delivery.notice.seq
            || ack.version != RETRACTION_VERSION
        {
            return Err(AckError::Mismatch);
        }
        if matches!(delivery.status, DeliveryStatus::Acknowledged { .. }) {
            return Ok(delivery.status.clone());
        }
        delivery.status = match ack.outcome {
            AckOutcome::FutureUseBlocked { scope } => {
                if !scope.contains(delivery.notice.scope) {
                    return Err(AckError::ScopeShort);
                }
                delivery.influenced_checkpoints = ack.influenced_checkpoints.clone();
                delivery.influenced_total = ack.influenced_total;
                DeliveryStatus::Acknowledged { at: now, scope }
            }
            AckOutcome::Rejected(reason) => DeliveryStatus::Rejected { reason },
        };
        Ok(delivery.status.clone())
    }

    /// Moves to a new owner key. Every live grant is re-signed with the new
    /// key (same terms), and the rotation is kept for delivery.
    pub fn rotate_key(&mut self, new: Keypair, now: u64) -> Result<KeyRotation, OwnerError> {
        self.seq += 1;
        let rotation = KeyRotation::new_signed(self.owner_id, &self.keypair, &new, self.seq, now);
        self.keypair = new;
        for record in self.packages.values_mut() {
            // Open notices must verify under the key recipients will accept.
            for delivery in record.deliveries.values_mut() {
                if !matches!(delivery.status, DeliveryStatus::Acknowledged { .. }) {
                    delivery.notice.sign_with(&self.keypair);
                }
            }
            if matches!(record.state, PackageState::Withdrawn { .. }) {
                continue;
            }
            for consent in record.grants.values_mut() {
                consent.sign_with(&self.keypair);
            }
        }
        self.rotation = Some(rotation.clone());
        Ok(rotation)
    }

    /// The latest key rotation sealed for one registered recipient.
    pub fn sealed_rotation(&self, recipient: Key) -> Result<Option<Vec<u8>>, OwnerError> {
        let keys = self
            .recipients
            .get(&recipient)
            .ok_or(OwnerError::UnregisteredRecipient)?;
        match &self.rotation {
            Some(rotation) => Ok(Some(seal(&keys.box_key, &rotation.to_bytes()?)?)),
            None => Ok(None),
        }
    }

    /// The owner's view: every package, recipient, use, license, expiry,
    /// training consent and retraction status. Remote erasure is never
    /// reported, only `NotVerifiablyErased`.
    pub fn view(&self) -> Vec<PackageView> {
        self.packages
            .iter()
            .map(|(package_id, record)| {
                let recipients: Vec<RecipientView> = record
                    .grants
                    .iter()
                    .map(|(recipient, consent)| {
                        let delivery = record.deliveries.get(recipient);
                        RecipientView {
                            recipient: *recipient,
                            uses: consent.uses,
                            training_consent: consent.uses.contains(Uses::TRAINING),
                            license: consent.license.clone(),
                            retention_end: consent.retention_end,
                            received: record.sent_to.contains(recipient),
                            retraction: delivery.map(|d| d.status.clone()),
                            influenced_checkpoints: delivery
                                .map(|d| d.influenced_checkpoints.clone())
                                .unwrap_or_default(),
                            influenced_total: delivery.map_or(0, |d| d.influenced_total),
                        }
                    })
                    .collect();
                // Any recipient that received the package with training
                // consent may have trained on it, reported or not.
                let trained = recipients
                    .iter()
                    .any(|r| r.influenced_total > 0 || (r.received && r.training_consent));
                PackageView {
                    package_id: *package_id,
                    state: record.state,
                    payload_retained: record.payload.is_some(),
                    uncontrolled_copies: (!record.sent_to.is_empty())
                        .then_some(ErasureStatus::NotVerifiablyErased),
                    trained_weights: trained.then_some(ErasureStatus::NotVerifiablyErased),
                    recipients,
                }
            })
            .collect()
    }

    /// The withdrawal receipt for a package, if withdrawn.
    pub fn receipt(&self, package_id: PackageId) -> Option<WithdrawalReceipt> {
        self.packages.get(&package_id)?.receipt.clone()
    }

    /// Delivery status of one recipient's notice for one package.
    pub fn delivery_status(&self, package_id: PackageId, recipient: Key) -> Option<DeliveryStatus> {
        Some(
            self.packages
                .get(&package_id)?
                .deliveries
                .get(&recipient)?
                .status
                .clone(),
        )
    }
}
