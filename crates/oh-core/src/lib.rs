//! Open Humanity volunteer compute, version 0, with teaching mode.
//!
//! Volunteers train a shared model locally and return only a signed,
//! compressed update. The coordinator scores each update in Turings
//! (held-out bits saved) and credits the volunteer. Design notes live in
//! `docs/design/volunteer-compute-v0.md`.

pub mod carrier;
pub mod identity;
pub mod learner;
pub mod scoring;
pub mod teacher;
pub mod transport;
pub mod update;
pub mod wire;

pub use identity::*;
pub use learner::*;
pub use scoring::*;
pub use teacher::*;
pub use transport::*;
pub use update::*;
pub use wire::*;
