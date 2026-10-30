//! The volunteer agent: runs on a Spark owner's machine, opens one outbound
//! connection to Drake's coordinator (no listening socket at all), proves
//! its key and its verified model, then answers jobs with the local engine.

use crate::engine::{Engine, EngineError};
use crate::http;
use crate::protocol::{hex, Attestation, Completion, CoordMsg, VolMsg, PROTOCOL};
use beacon_core::Keypair;
use oh_core::{recv, send, volunteer_handshake, CoordinatorPin};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VolunteerError {
    #[error("connection: {0}")]
    Io(String),
    #[error("the coordinator refused this Spark: {0}")]
    Refused(String),
    #[error("lending is suspended by the coordinator: {0}")]
    Suspended(String),
    #[error("the coordinator pins model {expected}, this Spark verified {got}")]
    ModelMismatch { expected: String, got: String },
    #[error("protocol: {0}")]
    Protocol(String),
}

/// What this volunteer serves, after `model::verify_model` passed.
pub struct VolunteerConfig {
    pub keypair: Keypair,
    pub coordinator_key: [u8; 32],
    pub host: String,
    pub path: String,
    pub model_id: String,
    pub model_digest: [u8; 32],
    pub engine_digest: [u8; 32],
    /// While this file exists the volunteer answers pings with
    /// `accepting: false` and turns down any job that arrives.
    pub pause_file: Option<PathBuf>,
}

impl VolunteerConfig {
    pub fn accepting(&self) -> bool {
        self.pause_file.as_ref().is_none_or(|p| !p.exists())
    }
}

/// What a session did, for the owner's log.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub answered: u64,
    pub failed: u64,
    pub pings: u64,
}

fn io<E: std::fmt::Display>(e: E) -> VolunteerError {
    VolunteerError::Io(e.to_string())
}

/// One session over an already connected stream (TCP or TLS). Returns when
/// the coordinator closes the connection. `log` receives one line per event
/// and never the chat text.
pub fn run_session<S: Read + Write>(
    mut stream: S,
    cfg: &VolunteerConfig,
    engine: &dyn Engine,
    log: &mut dyn FnMut(&str),
) -> Result<SessionReport, VolunteerError> {
    http::client_upgrade(&mut stream, &cfg.host, &cfg.path).map_err(io)?;
    let mut s = volunteer_handshake(
        stream,
        &cfg.keypair,
        CoordinatorPin::Key(cfg.coordinator_key),
    )
    .map_err(io)?;
    let (nonce, model_id, model_digest) = match recv(&mut s).map_err(io)? {
        CoordMsg::Challenge {
            protocol,
            nonce,
            model_id,
            model_digest,
        } if protocol == PROTOCOL => (nonce, model_id, model_digest),
        CoordMsg::Refused { reason } => return Err(VolunteerError::Refused(reason)),
        _ => return Err(VolunteerError::Protocol("expected a challenge".into())),
    };
    if model_digest != cfg.model_digest || model_id != cfg.model_id {
        return Err(VolunteerError::ModelMismatch {
            expected: format!("{model_id} {}", hex(&model_digest)),
            got: format!("{} {}", cfg.model_id, hex(&cfg.model_digest)),
        });
    }
    let att = Attestation::new_signed(
        &cfg.keypair,
        nonce,
        &cfg.model_id,
        cfg.model_digest,
        cfg.engine_digest,
    );
    send(&mut s, &VolMsg::Attest(att)).map_err(io)?;
    match recv(&mut s).map_err(io)? {
        CoordMsg::Accepted { .. } => log("attested; waiting for overflow chats"),
        CoordMsg::Refused { reason } => return Err(VolunteerError::Refused(reason)),
        _ => {
            return Err(VolunteerError::Protocol(
                "expected accepted or refused".into(),
            ))
        }
    }
    let mut report = SessionReport::default();
    loop {
        let msg: CoordMsg = match recv(&mut s) {
            Ok(m) => m,
            Err(oh_core::WireError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(report)
            }
            Err(e) => return Err(io(e)),
        };
        match msg {
            CoordMsg::Ping { nonce } => {
                report.pings += 1;
                send(
                    &mut s,
                    &VolMsg::Pong {
                        nonce,
                        accepting: cfg.accepting(),
                    },
                )
                .map_err(io)?;
            }
            CoordMsg::Job(job) => {
                if !cfg.accepting() {
                    send(
                        &mut s,
                        &VolMsg::Failed {
                            job_id: job.job_id,
                            reason: "paused by the owner".into(),
                        },
                    )
                    .map_err(io)?;
                    continue;
                }
                if job.model_id != cfg.model_id {
                    send(
                        &mut s,
                        &VolMsg::Failed {
                            job_id: job.job_id,
                            reason: "job names another model".into(),
                        },
                    )
                    .map_err(io)?;
                    continue;
                }
                let mut output = String::new();
                let mut write_err = None;
                let result = engine.generate(&job, &mut |piece: &str| {
                    output.push_str(piece);
                    send(
                        &mut s,
                        &VolMsg::Token {
                            job_id: job.job_id,
                            text: piece.to_string(),
                        },
                    )
                    .map_err(|e| {
                        let m = e.to_string();
                        write_err = Some(m.clone());
                        m
                    })
                });
                if let Some(e) = write_err {
                    return Err(VolunteerError::Io(e));
                }
                match result {
                    Ok(finish) => {
                        let done = Completion::new_signed(&cfg.keypair, &job, output, &finish);
                        send(&mut s, &VolMsg::Done(done)).map_err(io)?;
                        report.answered += 1;
                        log(&format!(
                            "answered one visitor (job {})",
                            hex(&job.job_id[..4])
                        ));
                    }
                    Err(e) => {
                        let reason = match e {
                            EngineError::Http(_) | EngineError::Io(_) | EngineError::Address(_) => {
                                "local engine unavailable"
                            }
                            EngineError::TooLarge => "reply too long",
                            _ => "local engine error",
                        };
                        send(
                            &mut s,
                            &VolMsg::Failed {
                                job_id: job.job_id,
                                reason: reason.into(),
                            },
                        )
                        .map_err(io)?;
                        report.failed += 1;
                        log(&format!("could not answer: {e}"));
                    }
                }
            }
            CoordMsg::Suspended { reason } => return Err(VolunteerError::Suspended(reason)),
            CoordMsg::Refused { reason } => return Err(VolunteerError::Refused(reason)),
            _ => return Err(VolunteerError::Protocol("unexpected message".into())),
        }
    }
}
