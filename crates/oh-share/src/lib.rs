//! Owner-controlled sharing for Open Humanity: consent, Discovery Capsules,
//! signed withdrawal with per-recipient acknowledgements, and the capsule
//! receiver (issues #33 and #34).
//!
//! Invariants:
//! - Private by default. A package leaves the owner's machine only through
//!   an explicit `OwnerLedger::publish` to one registered, granted recipient.
//! - Withdrawal is local and works offline: the owner's gate closes at once
//!   and the withdrawn text is dropped from the ledger; signed notices then
//!   go to every permitted recipient and stay `Pending` until a verified
//!   signed ack arrives, or `Unreachable` once the retry window closes.
//! - A recipient records the tombstone before it signs the ack, and its use
//!   gate refuses serving, republishing, indexing and training of withdrawn
//!   uses.
//! - Nothing claims remote erasure. Copies outside participating nodes and
//!   weights already trained on a package are `NotVerifiablyErased`;
//!   affected checkpoints are quarantined, never reported as unlearned.
//! - A received capsule is untrusted data. The receiver re-checks every
//!   signature, digest, consent, license, revocation, environment and
//!   capability itself, and reproduction and native qualification remain
//!   separate stages that only the receiver's own verifier can move.
//!
//! The message encodings mirror the aien-protocols #51 draft field names
//! (`OwnerConsentV1`, `DiscoveryCapsuleV1`, `OwnerRetractionV1`) but the
//! bytes are local and provisional until that crate publishes the
//! canonical encoding.

pub mod codec;
pub mod consent;
pub mod net;
pub mod owner;
pub mod recipient;
pub mod retraction;

pub use consent::*;
pub use owner::*;
pub use recipient::*;
pub use retraction::*;
