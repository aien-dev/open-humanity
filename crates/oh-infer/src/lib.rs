//! Open Humanity volunteer inference, version 0.
//!
//! Spark owners who opt in lend their local Sovereign Intelligence engine to
//! answer Allen's visitors when Drake's Spark is at its public cap, and only
//! for visitors who opted in too. Design and threat model:
//! `docs/design/volunteer-inference-v0.md`.
//!
//! Rust today, recorded with its Omega successor in that document.

pub mod bearer;
pub mod coordinator;
pub mod engine;
pub mod http;
pub mod model;
pub mod protocol;
pub mod tls;
pub mod volunteer;
