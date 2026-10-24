//! Signed retraction notices, recipient acknowledgements and owner key
//! rotation.
//!
//! Field names follow the aien-protocols #51 draft `OwnerRetractionV1`; the
//! bytes are Open Humanity local and provisional until that crate lands.
//!
//! What a retraction can and cannot do: a notice asks one registered
//! recipient to stop all future serving, republication, indexing and
//! training of one package. An acknowledgement attests only that this
//! recipient now refuses those uses. No message in this module can state
//! that a copy was erased: copies outside participating nodes and weights
//! already trained on the package stay `NotVerifiablyErased`.

use crate::codec::{signature_ok, signed_message, MAX_CONTROL_BYTES};
use crate::consent::{Key, PackageId, Uses};
use beacon_core::Keypair;
use serde::{Deserialize, Serialize};

pub const RETRACTION_VERSION: u16 = 1;
/// Most checkpoint ids one ack lists; `influenced_total` carries the count.
/// Keeps the largest ack well under `MAX_CONTROL_BYTES`.
pub const MAX_LISTED_CHECKPOINTS: usize = 128;

/// The owner's signed request that one recipient stop future use of one
/// package. One notice per recipient, so a notice cannot be replayed at a
/// different recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetractionNotice {
    pub version: u16,
    pub notice_id: [u8; 16],
    pub owner_id: Key,
    /// The owner's current key or a custodian the consent declared.
    pub signer: Key,
    pub recipient: Key,
    pub package_id: PackageId,
    /// Uses withdrawn. Withdrawal is permanent: no message re-grants them.
    pub scope: Uses,
    /// Monotonic per owner.
    pub seq: u64,
    pub issued_at: u64,
    /// The owner stops retrying after this time and reports the recipient
    /// as unreachable. A recipient still enforces a genuine late notice.
    pub retry_until: u64,
    pub sig: Vec<u8>,
}

signed_message!(
    RetractionNotice,
    signer,
    b"open-humanity share v1: retraction notice\0",
    MAX_CONTROL_BYTES
);

/// Why a recipient refused a notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NoticeRejectReason {
    BadSignature,
    WrongRecipient,
    /// Signed by an owner key that a rotation retired.
    StaleKey,
    /// Signed by a key that is neither the owner nor a declared custodian.
    UnauthorizedSigner,
    UnknownScope,
    UnsupportedVersion,
}

/// What an acknowledgement attests. There is deliberately no variant for
/// erasure: an ack cannot claim that copies or trained weights are gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckOutcome {
    /// This recipient now refuses every use in `scope` for the package.
    FutureUseBlocked {
        scope: Uses,
    },
    Rejected(NoticeRejectReason),
}

/// A recipient's signed answer to one notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetractionAck {
    pub version: u16,
    /// `RetractionNotice::digest` of the notice answered.
    pub notice_digest: [u8; 32],
    pub owner_id: Key,
    pub package_id: PackageId,
    pub seq: u64,
    pub recipient: Key,
    pub outcome: AckOutcome,
    /// Checkpoints (aien-train provenance ids) the recipient had already
    /// trained on the package, at most `MAX_LISTED_CHECKPOINTS` of them.
    /// They are quarantined, not unlearned.
    pub influenced_checkpoints: Vec<[u8; 16]>,
    /// How many distinct checkpoints trained on the package in total.
    pub influenced_total: u64,
    pub acked_at: u64,
    pub sig: Vec<u8>,
}

signed_message!(
    RetractionAck,
    recipient,
    b"open-humanity share v1: retraction ack\0",
    MAX_CONTROL_BYTES
);

/// The only erasure status this crate ever reports for copies held outside
/// the owner's machine and for trained weights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErasureStatus {
    NotVerifiablyErased,
}

/// The owner moves from `old_key` to `new_key`. Signed by both keys, so
/// neither a stolen old key alone nor an unrelated key can rotate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    pub version: u16,
    pub owner_id: Key,
    pub old_key: Key,
    pub new_key: Key,
    pub seq: u64,
    pub issued_at: u64,
    pub sig_old: Vec<u8>,
    pub sig_new: Vec<u8>,
}

const ROTATION_CONTEXT: &[u8] = b"open-humanity share v1: key rotation\0";

impl KeyRotation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig_old = Vec::new();
        unsigned.sig_new = Vec::new();
        let mut out = ROTATION_CONTEXT.to_vec();
        out.extend_from_slice(
            &crate::codec::encode(&unsigned, u64::MAX).expect("plain structs always encode"),
        );
        out
    }

    pub fn new_signed(
        owner_id: Key,
        old: &Keypair,
        new: &Keypair,
        seq: u64,
        issued_at: u64,
    ) -> Self {
        let mut rotation = Self {
            version: RETRACTION_VERSION,
            owner_id,
            old_key: old.pubkey_bytes(),
            new_key: new.pubkey_bytes(),
            seq,
            issued_at,
            sig_old: Vec::new(),
            sig_new: Vec::new(),
        };
        let bytes = rotation.signing_bytes();
        rotation.sig_old = old.sign(&bytes).to_vec();
        rotation.sig_new = new.sign(&bytes).to_vec();
        rotation
    }

    pub fn signatures_valid(&self) -> bool {
        let bytes = self.signing_bytes();
        signature_ok(&self.old_key, &bytes, &self.sig_old)
            && signature_ok(&self.new_key, &bytes, &self.sig_new)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        crate::codec::encode(self, MAX_CONTROL_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::codec::CodecError> {
        crate::codec::decode(bytes, MAX_CONTROL_BYTES)
    }
}
