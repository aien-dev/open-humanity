//! Open Humanity volunteer compute, version 0.
//!
//! Volunteers train a shared model locally and return only a signed,
//! compressed update. The coordinator scores each update in Turings
//! (held-out bits saved) and credits the volunteer. Design notes live in
//! `docs/design/volunteer-compute-v0.md`.

pub mod learner;

pub use learner::*;
