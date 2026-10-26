//! The coordinator, on Drake's side. It holds volunteer sessions (outbound
//! connections from volunteers, upgraded from HTTP so they pass through
//! nginx), routes overflow chats from the Allen gateway to a healthy
//! volunteer, streams the reply back, and keeps the volunteers honest:
//!
//! * a model attestation on every session, checked against the pinned
//!   manifest digest;
//! * every reply signed by the volunteer, and the signed text must equal
//!   the streamed text;
//! * a sample of replies queued for replay on Drake's engine with the same
//!   greedy decoding; a reply that differs suspends the volunteer;
//! * a reputation score that orders volunteers, and per-volunteer caps of
//!   one reply at a time and a number of replies per hour.
//!
//! What this cannot stop: a volunteer that returns bad text on a reply that
//! was not sampled. The visitor disclosure says so.
//!
//! Privacy: the gateway request type accepts only `volunteer_consent` and
//! user and assistant messages (`deny_unknown_fields`); requests carrying a
//! visitor key, cookie or any other field are refused before routing. No
//! visitor text is written to disk: the replay queue is memory only and the
//! event log holds digests.

use crate::engine::request_body;
use crate::http::{self, read_request, write_error, write_response};
use crate::protocol::{
    hex, Attestation, ChatMessage, Completion, CoordMsg, Job, Role, VolMsg, MAX_MESSAGES,
    MAX_MESSAGE_BYTES, MAX_OUTPUT_BYTES, PROTOCOL,
};
use beacon_core::Keypair;
use oh_core::{coordinator_handshake, recv, send, EncryptedStream};
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// 18096 is taken on Drake's Spark (Allen's visitor memory); keep clear of it.
pub const DEFAULT_VOLUNTEER_LISTEN: &str = "127.0.0.1:18136";
pub const DEFAULT_API_LISTEN: &str = "127.0.0.1:18137";
pub const DEFAULT_UPGRADE_PATH: &str = "/oh/v1/volunteer";
/// Largest gateway request body.
pub const MAX_API_BODY: usize = 256 * 1024;
/// Reputation lost on a divergent sampled reply.
pub const DIVERGENCE_PENALTY: i64 = 100;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    pub model_id: String,
    /// SHA-256 of the pinned model manifest.
    pub model_digest: [u8; 32],
    /// If set, the engine binary digest a volunteer must attest.
    pub engine_digest: Option<[u8; 32]>,
    /// Allen's public anonymous system prompt, added by the coordinator.
    /// The gateway may not send a system message.
    pub system_prompt: Option<String>,
    /// Registered volunteer keys given on the command line.
    pub approved: HashSet<[u8; 32]>,
    /// Re-read on every new volunteer connection, one hex key per line.
    pub approved_file: Option<PathBuf>,
    /// Overflow routing. Off by default; while off, every overflow request
    /// gets 503 and no visitor text reaches any volunteer.
    pub routing_enabled: bool,
    pub sample_rate: f64,
    /// Sample rate until a volunteer has `probation_jobs` verified replies.
    pub probation_sample_rate: f64,
    pub probation_jobs: u64,
    pub max_jobs_per_hour: usize,
    pub max_tokens_cap: u32,
    pub first_token_timeout: Duration,
    pub token_timeout: Duration,
    pub job_timeout: Duration,
    pub ping_interval: Duration,
    pub replay_queue_cap: usize,
    /// Where reputation and suspensions persist (`volunteers.json`) and the
    /// digest-only event log goes (`events.jsonl`). None keeps state in memory.
    pub state_dir: Option<PathBuf>,
    pub upgrade_path: String,
    /// Fixes the sampling draws (tests).
    pub sampling_seed: Option<u64>,
}

impl CoordinatorConfig {
    pub fn new(model_id: &str, model_digest: [u8; 32]) -> Self {
        Self {
            model_id: model_id.to_string(),
            model_digest,
            engine_digest: None,
            system_prompt: None,
            approved: HashSet::new(),
            approved_file: None,
            routing_enabled: false,
            sample_rate: 0.1,
            probation_sample_rate: 0.5,
            probation_jobs: 20,
            max_jobs_per_hour: 60,
            max_tokens_cap: 1024,
            first_token_timeout: Duration::from_secs(60),
            token_timeout: Duration::from_secs(30),
            job_timeout: Duration::from_secs(300),
            ping_interval: Duration::from_secs(15),
            replay_queue_cap: 256,
            state_dir: None,
            upgrade_path: DEFAULT_UPGRADE_PATH.to_string(),
            sampling_seed: None,
        }
    }
}

/// Persistent per-volunteer record.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub reputation: i64,
    pub served: u64,
    pub verified: u64,
    pub diverged: u64,
    pub failed: u64,
    pub suspended: Option<String>,
}

/// One message from the gateway. Only these fields are accepted; anything
/// else (a visitor key, memory, contact, name, address) makes serde refuse
/// the whole request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverflowRequest {
    pub volunteer_consent: bool,
    pub messages: Vec<OverflowMessage>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverflowMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("volunteer routing is off")]
    Disabled,
    #[error("the visitor did not choose to let a volunteer answer")]
    NoConsent,
    #[error("request refused: {0}")]
    BadRequest(String),
    #[error("no volunteer is available")]
    NoVolunteer,
}

impl RouteError {
    pub fn status(&self) -> u16 {
        match self {
            RouteError::Disabled | RouteError::NoVolunteer => 503,
            RouteError::NoConsent => 403,
            RouteError::BadRequest(_) => 400,
        }
    }
}

/// What the gateway reads while a volunteer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Token(String),
    Done { finish_reason: String },
    Failed(String),
}

/// A routed request: who answers, and the event stream.
pub struct Routed {
    pub volunteer: [u8; 32],
    pub model_id: String,
    pub events: Receiver<StreamEvent>,
}

/// A sampled reply waiting for (or taken for) replay on Drake's engine.
#[derive(Debug, Clone)]
struct Replay {
    volunteer: [u8; 32],
    job: Job,
    completion: Completion,
}

/// Handed to the gateway to replay on the reference engine.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayTask {
    pub replay_id: u64,
    /// The exact OpenAI-style request body (greedy, seeded, not streamed).
    pub request: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub replay_id: u64,
    pub volunteer: String,
    /// "match" or "diverged".
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub routing_enabled: bool,
    pub model_id: String,
    pub model_digest: String,
    pub connected: usize,
    pub healthy: usize,
    pub busy: usize,
    pub suspended: usize,
    pub replay_waiting: usize,
    pub replay_taken: usize,
    pub replay_dropped: u64,
}

enum Command {
    Job {
        job: Job,
        sampled: bool,
        events: Sender<StreamEvent>,
    },
    Suspend(String),
}

struct Session {
    id: u64,
    tx: Sender<Command>,
    busy: bool,
    accepting: bool,
    last_seen: Instant,
    last_used: Instant,
}

#[derive(Default)]
struct State {
    records: BTreeMap<[u8; 32], Record>,
    sessions: HashMap<[u8; 32], Session>,
    recent: HashMap<[u8; 32], VecDeque<Instant>>,
    replays: VecDeque<Replay>,
    taken: HashMap<u64, Replay>,
    next_replay_id: u64,
    next_session_id: u64,
    replay_dropped: u64,
}

struct Shared {
    cfg: CoordinatorConfig,
    keypair: Keypair,
    state: Mutex<State>,
    rng: Mutex<rand::rngs::StdRng>,
}

/// The coordinator. Cheap to clone; all clones share state.
#[derive(Clone)]
pub struct Coordinator {
    shared: Arc<Shared>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(text: &str) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(text.as_bytes()))
}

impl Coordinator {
    pub fn new(cfg: CoordinatorConfig, keypair: Keypair) -> Result<Self, String> {
        let mut state = State::default();
        if let Some(dir) = &cfg.state_dir {
            std::fs::create_dir_all(dir).map_err(|e| format!("state dir: {e}"))?;
            let path = dir.join("volunteers.json");
            if path.exists() {
                let text = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                let map: BTreeMap<String, Record> = serde_json::from_slice(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                for (k, v) in map {
                    let key = oh_core::parse_key(&k)
                        .ok_or_else(|| format!("{}: bad key {k:?}", path.display()))?;
                    state.records.insert(key, v);
                }
            }
        }
        let rng = match cfg.sampling_seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s),
            None => rand::rngs::StdRng::from_entropy(),
        };
        Ok(Self {
            shared: Arc::new(Shared {
                cfg,
                keypair,
                state: Mutex::new(state),
                rng: Mutex::new(rng),
            }),
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.shared.keypair.pubkey_bytes()
    }

    pub fn config(&self) -> &CoordinatorConfig {
        &self.shared.cfg
    }

    pub fn record(&self, key: &[u8; 32]) -> Record {
        self.lock().records.get(key).cloned().unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn event(&self, value: serde_json::Value) {
        let Some(dir) = &self.shared.cfg.state_dir else {
            return;
        };
        let mut line = value.to_string();
        line.push('\n');
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.jsonl"))
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn persist(&self, state: &State) {
        let Some(dir) = &self.shared.cfg.state_dir else {
            return;
        };
        let map: BTreeMap<String, &Record> =
            state.records.iter().map(|(k, v)| (hex(k), v)).collect();
        let tmp = dir.join("volunteers.json.tmp");
        let body = serde_json::to_vec_pretty(&map).expect("records encode");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, dir.join("volunteers.json"));
        }
    }

    fn is_approved(&self, key: &[u8; 32]) -> bool {
        if self.shared.cfg.approved.contains(key) {
            return true;
        }
        let Some(path) = &self.shared.cfg.approved_file else {
            return false;
        };
        std::fs::read_to_string(path).is_ok_and(|text| {
            text.lines()
                .map(|l| l.split('#').next().unwrap_or("").trim())
                .filter_map(oh_core::parse_key)
                .any(|k| &k == key)
        })
    }

    /// Clears a suspension (operator action after reviewing the evidence).
    pub fn reinstate(&self, key: &[u8; 32]) -> bool {
        let mut st = self.lock();
        let changed = match st.records.get_mut(key) {
            Some(r) if r.suspended.is_some() => {
                r.suspended = None;
                true
            }
            _ => false,
        };
        if changed {
            self.persist(&st);
            drop(st);
            self.event(
                serde_json::json!({"t": now_secs(), "event": "reinstated", "volunteer": hex(key)}),
            );
        }
        changed
    }

    pub fn status(&self) -> Status {
        let st = self.lock();
        let healthy = st
            .sessions
            .iter()
            .filter(|(k, s)| self.healthy(&st, k, s))
            .count();
        Status {
            routing_enabled: self.shared.cfg.routing_enabled,
            model_id: self.shared.cfg.model_id.clone(),
            model_digest: hex(&self.shared.cfg.model_digest),
            connected: st.sessions.len(),
            healthy,
            busy: st.sessions.values().filter(|s| s.busy).count(),
            suspended: st
                .records
                .values()
                .filter(|r| r.suspended.is_some())
                .count(),
            replay_waiting: st.replays.len(),
            replay_taken: st.taken.len(),
            replay_dropped: st.replay_dropped,
        }
    }

    fn healthy(&self, st: &State, key: &[u8; 32], s: &Session) -> bool {
        let fresh = s.last_seen.elapsed() <= self.shared.cfg.ping_interval * 3;
        let suspended = st.records.get(key).is_some_and(|r| r.suspended.is_some());
        let hour_ago = Instant::now().checked_sub(Duration::from_secs(3600));
        let used = st.recent.get(key).map_or(0, |q| {
            q.iter()
                .filter(|t| hour_ago.is_none_or(|h| **t > h))
                .count()
        });
        s.accepting && fresh && !suspended && used < self.shared.cfg.max_jobs_per_hour
    }

    /// Checks and converts a gateway request into the messages a volunteer
    /// will see. Nothing but role and content survives.
    pub fn build_messages(&self, req: &OverflowRequest) -> Result<Vec<ChatMessage>, RouteError> {
        if !req.volunteer_consent {
            return Err(RouteError::NoConsent);
        }
        if req.messages.is_empty() || req.messages.len() > MAX_MESSAGES {
            return Err(RouteError::BadRequest("1 to 64 messages".into()));
        }
        let mut out = Vec::with_capacity(req.messages.len() + 1);
        if let Some(sp) = &self.shared.cfg.system_prompt {
            out.push(ChatMessage {
                role: Role::System,
                content: sp.clone(),
            });
        }
        for m in &req.messages {
            let role = match m.role.as_str() {
                "user" => Role::User,
                "assistant" => Role::Assistant,
                other => {
                    return Err(RouteError::BadRequest(format!(
                        "role {other:?} is not accepted; only user and assistant"
                    )))
                }
            };
            if m.content.len() > MAX_MESSAGE_BYTES {
                return Err(RouteError::BadRequest("message too long".into()));
            }
            out.push(ChatMessage {
                role,
                content: m.content.clone(),
            });
        }
        if out.last().map(|m| m.role) != Some(Role::User) {
            return Err(RouteError::BadRequest(
                "the last message must be the visitor's".into(),
            ));
        }
        Ok(out)
    }

    /// Routes one overflow chat to the best healthy volunteer.
    pub fn route(&self, req: &OverflowRequest) -> Result<Routed, RouteError> {
        if !self.shared.cfg.routing_enabled {
            return Err(RouteError::Disabled);
        }
        let messages = self.build_messages(req)?;
        let max_tokens = req
            .max_tokens
            .unwrap_or(self.shared.cfg.max_tokens_cap)
            .clamp(1, self.shared.cfg.max_tokens_cap);
        loop {
            let mut job_id = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut job_id);
            let job = Job {
                job_id,
                model_id: self.shared.cfg.model_id.clone(),
                messages: messages.clone(),
                max_tokens,
                seed: 0,
            };
            let mut st = self.lock();
            let mut candidates: Vec<([u8; 32], i64, Instant)> = st
                .sessions
                .iter()
                .filter(|(k, s)| !s.busy && self.healthy(&st, k, s))
                .map(|(k, s)| {
                    let rep = st.records.get(k).map_or(0, |r| r.reputation);
                    (*k, rep, s.last_used)
                })
                .collect();
            candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
            let Some((key, _, _)) = candidates.first().copied() else {
                return Err(RouteError::NoVolunteer);
            };
            let verified = st.records.get(&key).map_or(0, |r| r.verified);
            let rate = if verified < self.shared.cfg.probation_jobs {
                self.shared.cfg.probation_sample_rate
            } else {
                self.shared.cfg.sample_rate
            };
            let sampled = self
                .shared
                .rng
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .gen_bool(rate.clamp(0.0, 1.0));
            let (tx, rx) = mpsc::channel();
            let session = st.sessions.get_mut(&key).expect("candidate exists");
            if session
                .tx
                .send(Command::Job {
                    job,
                    sampled,
                    events: tx,
                })
                .is_err()
            {
                st.sessions.remove(&key);
                continue;
            }
            session.busy = true;
            session.last_used = Instant::now();
            st.recent.entry(key).or_default().push_back(Instant::now());
            if let Some(q) = st.recent.get_mut(&key) {
                while q.len() > self.shared.cfg.max_jobs_per_hour {
                    q.pop_front();
                }
            }
            return Ok(Routed {
                volunteer: key,
                model_id: self.shared.cfg.model_id.clone(),
                events: rx,
            });
        }
    }

    /// The next sampled reply to replay on Drake's engine, if any.
    pub fn next_replay(&self) -> Option<ReplayTask> {
        let mut st = self.lock();
        let r = st.replays.pop_front()?;
        st.next_replay_id += 1;
        let id = st.next_replay_id;
        let mut request = request_body(&r.job);
        request["stream"] = serde_json::Value::Bool(false);
        st.taken.insert(id, r);
        Some(ReplayTask {
            replay_id: id,
            request,
        })
    }

    /// Compares Drake's engine output with the volunteer's signed reply. A
    /// difference suspends the volunteer and records digest-only evidence.
    pub fn submit_replay(&self, replay_id: u64, reference_output: &str) -> Option<Verdict> {
        let mut st = self.lock();
        let r = st.taken.remove(&replay_id)?;
        let matched = r.completion.output == reference_output;
        let rec = st.records.entry(r.volunteer).or_default();
        if matched {
            rec.reputation += 1;
            rec.verified += 1;
        } else {
            rec.reputation -= DIVERGENCE_PENALTY;
            rec.diverged += 1;
            rec.suspended = Some(format!(
                "sampled reply diverged from the reference engine (job {})",
                hex(&r.job.digest()[..8])
            ));
        }
        let session_tx = st.sessions.get(&r.volunteer).map(|s| s.tx.clone());
        self.persist(&st);
        drop(st);
        let verdict = if matched { "match" } else { "diverged" };
        self.event(serde_json::json!({
            "t": now_secs(),
            "event": "replay",
            "verdict": verdict,
            "volunteer": hex(&r.volunteer),
            "job_digest": hex(&r.job.digest()),
            "volunteer_output_sha256": sha256_hex(&r.completion.output),
            "reference_output_sha256": sha256_hex(reference_output),
            "volunteer_signature": hex(&r.completion.sig),
        }));
        if !matched {
            if let Some(tx) = session_tx {
                let _ = tx.send(Command::Suspend(
                    "a sampled reply did not match Drake's engine; lending is suspended until reviewed"
                        .into(),
                ));
            }
        }
        Some(Verdict {
            replay_id,
            volunteer: hex(&r.volunteer),
            verdict: verdict.into(),
        })
    }

    fn push_replay(&self, r: Replay) {
        let mut st = self.lock();
        if st.replays.len() >= self.shared.cfg.replay_queue_cap {
            st.replays.pop_front();
            st.replay_dropped += 1;
        }
        st.replays.push_back(r);
    }

    fn mark(&self, key: &[u8; 32], f: impl FnOnce(&mut Record)) {
        let mut st = self.lock();
        f(st.records.entry(*key).or_default());
        self.persist(&st);
    }

    fn set_idle(&self, key: &[u8; 32], session_id: u64) {
        let mut st = self.lock();
        if let Some(s) = st.sessions.get_mut(key) {
            if s.id == session_id {
                s.busy = false;
                s.last_seen = Instant::now();
            }
        }
    }

    fn drop_session(&self, key: &[u8; 32], session_id: u64) {
        let mut st = self.lock();
        if st.sessions.get(key).is_some_and(|s| s.id == session_id) {
            st.sessions.remove(key);
        }
    }

    /// Accepts volunteer connections forever, one thread each.
    pub fn serve_volunteers(&self, listener: TcpListener) {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let me = self.clone();
            thread::spawn(move || {
                if let Err(e) = me.volunteer_session(stream) {
                    eprintln!("oh-infer: volunteer session ended: {e}");
                }
            });
        }
    }

    fn volunteer_session(&self, mut stream: TcpStream) -> Result<(), String> {
        let cfg = &self.shared.cfg;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .and_then(|_| stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)))
            .map_err(|e| e.to_string())?;
        http::server_upgrade(&mut stream, &cfg.upgrade_path).map_err(|e| e.to_string())?;
        let mut s =
            coordinator_handshake(stream, &self.shared.keypair).map_err(|e| e.to_string())?;
        let peer = s.peer_identity();
        let refuse = |s: &mut EncryptedStream<TcpStream>, reason: String| {
            let _ = send(
                s,
                &CoordMsg::Refused {
                    reason: reason.clone(),
                },
            );
            self.event(serde_json::json!({"t": now_secs(), "event": "refused", "volunteer": hex(&peer), "reason": reason}));
            Err(reason)
        };
        if !self.is_approved(&peer) {
            return refuse(
                &mut s,
                "this key is not registered with the coordinator".into(),
            );
        }
        if let Some(reason) = self.record(&peer).suspended {
            return refuse(&mut s, format!("suspended: {reason}"));
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        send(
            &mut s,
            &CoordMsg::Challenge {
                protocol: PROTOCOL,
                nonce,
                model_id: cfg.model_id.clone(),
                model_digest: cfg.model_digest,
            },
        )
        .map_err(|e| e.to_string())?;
        let att: Attestation = match recv(&mut s).map_err(|e| e.to_string())? {
            VolMsg::Attest(a) => a,
            _ => return refuse(&mut s, "expected an attestation".into()),
        };
        if let Err(e) = att.verify(&peer, &nonce) {
            return refuse(&mut s, format!("attestation refused: {e}"));
        }
        if att.model_digest != cfg.model_digest || att.model_id != cfg.model_id {
            return refuse(
                &mut s,
                format!(
                    "model hash {} is not the pinned {}; this Spark cannot serve",
                    hex(&att.model_digest),
                    hex(&cfg.model_digest)
                ),
            );
        }
        if let Some(e) = cfg.engine_digest {
            if att.engine_digest != e {
                return refuse(
                    &mut s,
                    format!(
                        "engine hash {} is not the pinned {}",
                        hex(&att.engine_digest),
                        hex(&e)
                    ),
                );
            }
        }
        send(&mut s, &CoordMsg::Accepted { max_inflight: 1 }).map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel();
        let id = {
            let mut st = self.lock();
            st.next_session_id += 1;
            let id = st.next_session_id;
            st.sessions.insert(
                peer,
                Session {
                    id,
                    tx,
                    busy: false,
                    accepting: true,
                    last_seen: Instant::now(),
                    last_used: Instant::now(),
                },
            );
            id
        };
        self.event(serde_json::json!({"t": now_secs(), "event": "attested", "volunteer": hex(&peer), "model_digest": hex(&att.model_digest), "engine_digest": hex(&att.engine_digest)}));
        let result = self.session_loop(&mut s, peer, id, rx);
        self.drop_session(&peer, id);
        result
    }

    fn session_loop(
        &self,
        s: &mut EncryptedStream<TcpStream>,
        peer: [u8; 32],
        id: u64,
        rx: Receiver<Command>,
    ) -> Result<(), String> {
        let cfg = &self.shared.cfg;
        let mut ping = 0u64;
        loop {
            match rx.recv_timeout(cfg.ping_interval) {
                Ok(Command::Job {
                    job,
                    sampled,
                    events,
                }) => {
                    let r = self.run_job(s, peer, &job, sampled, &events);
                    self.set_idle(&peer, id);
                    r?;
                }
                Ok(Command::Suspend(reason)) => {
                    let _ = send(
                        s,
                        &CoordMsg::Suspended {
                            reason: reason.clone(),
                        },
                    );
                    return Err(format!("suspended {}: {reason}", hex(&peer[..8])));
                }
                Err(RecvTimeoutError::Timeout) => {
                    ping += 1;
                    set_timeout(s, cfg.token_timeout)?;
                    send(s, &CoordMsg::Ping { nonce: ping }).map_err(|e| e.to_string())?;
                    match recv(s).map_err(|e| e.to_string())? {
                        VolMsg::Pong { nonce, accepting } if nonce == ping => {
                            let mut st = self.lock();
                            if let Some(x) = st.sessions.get_mut(&peer) {
                                if x.id == id {
                                    x.accepting = accepting;
                                    x.last_seen = Instant::now();
                                }
                            }
                        }
                        _ => return Err("expected a pong".into()),
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }

    fn run_job(
        &self,
        s: &mut EncryptedStream<TcpStream>,
        peer: [u8; 32],
        job: &Job,
        sampled: bool,
        events: &Sender<StreamEvent>,
    ) -> Result<(), String> {
        let cfg = &self.shared.cfg;
        let fail = |events: &Sender<StreamEvent>, why: &str| {
            let _ = events.send(StreamEvent::Failed(why.to_string()));
        };
        if let Err(e) = send(s, &CoordMsg::Job(job.clone())) {
            fail(events, "volunteer connection lost");
            return Err(e.to_string());
        }
        let deadline = Instant::now() + cfg.job_timeout;
        let mut streamed = String::new();
        let mut first = true;
        loop {
            let per = if first {
                cfg.first_token_timeout
            } else {
                cfg.token_timeout
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                fail(events, "volunteer took too long");
                self.mark(&peer, |r| {
                    r.failed += 1;
                    r.reputation -= 1;
                });
                return Err("job deadline passed".into());
            }
            set_timeout(s, per.min(left))?;
            let msg: VolMsg = match recv(s) {
                Ok(m) => m,
                Err(e) => {
                    fail(events, "volunteer stopped answering");
                    self.mark(&peer, |r| {
                        r.failed += 1;
                        r.reputation -= 1;
                    });
                    return Err(e.to_string());
                }
            };
            first = false;
            match msg {
                VolMsg::Token { job_id, text } if job_id == job.job_id => {
                    if streamed.len() + text.len() > MAX_OUTPUT_BYTES {
                        fail(events, "volunteer reply too long");
                        return Err("reply over the size cap".into());
                    }
                    streamed.push_str(&text);
                    let _ = events.send(StreamEvent::Token(text));
                }
                VolMsg::Done(c) => {
                    if let Err(e) = c.verify(&peer, job) {
                        fail(events, "volunteer reply failed verification");
                        return Err(format!("completion refused: {e}"));
                    }
                    if c.output != streamed {
                        // Signed text differs from what was streamed: the
                        // volunteer contradicted itself. Suspend.
                        fail(events, "volunteer reply failed verification");
                        let mut st = self.lock();
                        let rec = st.records.entry(peer).or_default();
                        rec.reputation -= DIVERGENCE_PENALTY;
                        rec.diverged += 1;
                        rec.suspended = Some("signed reply differs from streamed reply".into());
                        self.persist(&st);
                        drop(st);
                        self.event(serde_json::json!({"t": now_secs(), "event": "stream_mismatch", "volunteer": hex(&peer), "job_digest": hex(&job.digest())}));
                        let _ = send(
                            s,
                            &CoordMsg::Suspended {
                                reason: "signed reply differs from streamed reply".into(),
                            },
                        );
                        return Err("stream mismatch".into());
                    }
                    self.mark(&peer, |r| r.served += 1);
                    let _ = events.send(StreamEvent::Done {
                        finish_reason: c.finish_reason.clone(),
                    });
                    if sampled {
                        self.push_replay(Replay {
                            volunteer: peer,
                            job: job.clone(),
                            completion: c,
                        });
                    }
                    return Ok(());
                }
                VolMsg::Failed { job_id, reason } if job_id == job.job_id => {
                    let reason: String = reason.chars().take(200).collect();
                    fail(events, &format!("volunteer could not answer: {reason}"));
                    self.mark(&peer, |r| r.failed += 1);
                    return Ok(());
                }
                _ => {
                    fail(events, "volunteer broke the protocol");
                    return Err("unexpected message during a job".into());
                }
            }
        }
    }

    /// Serves the gateway API forever, one thread per connection. Bind it
    /// to loopback; nginx exposes it to the gateway's tailnet address only.
    pub fn serve_api(&self, listener: TcpListener) {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let me = self.clone();
            thread::spawn(move || {
                let _ = me.api_connection(stream);
            });
        }
    }

    fn api_connection(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let req = match read_request(&mut stream, MAX_API_BODY) {
            Ok(r) => r,
            Err(e) => return write_error(&mut stream, 400, &e.to_string()),
        };
        let path = req.head.second.split('?').next().unwrap_or("").to_string();
        match (req.head.first.as_str(), path.as_str()) {
            ("POST", "/v1/overflow") => self.api_overflow(&mut stream, &req),
            ("GET", "/v1/status") => {
                let body = serde_json::to_vec(&self.status()).expect("status encodes");
                write_response(&mut stream, 200, "application/json", &body)
            }
            ("GET", "/v1/replay/next") => match self.next_replay() {
                Some(t) => {
                    let body = serde_json::to_vec(&t).expect("task encodes");
                    write_response(&mut stream, 200, "application/json", &body)
                }
                None => write_response(&mut stream, 204, "application/json", b""),
            },
            ("POST", "/v1/replay/result") => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ReplayResult {
                    replay_id: u64,
                    output: String,
                }
                let r: ReplayResult = match serde_json::from_slice(&req.body) {
                    Ok(r) => r,
                    Err(e) => return write_error(&mut stream, 400, &e.to_string()),
                };
                match self.submit_replay(r.replay_id, &r.output) {
                    Some(v) => {
                        let body = serde_json::to_vec(&v).expect("verdict encodes");
                        write_response(&mut stream, 200, "application/json", &body)
                    }
                    None => write_error(&mut stream, 404, "no such replay"),
                }
            }
            _ => write_error(&mut stream, 404, "not found"),
        }
    }

    fn api_overflow(&self, stream: &mut TcpStream, req: &http::Request) -> std::io::Result<()> {
        for h in [
            "x-allen-key",
            "cookie",
            "authorization",
            "x-forwarded-for",
            "x-real-ip",
        ] {
            if req.head.header(h).is_some() {
                return write_error(
                    stream,
                    403,
                    &format!(
                        "header {h} is refused: only anonymous chat text may reach a volunteer"
                    ),
                );
            }
        }
        let parsed: OverflowRequest = match serde_json::from_slice(&req.body) {
            Ok(r) => r,
            Err(e) => return write_error(stream, 400, &format!("request refused: {e}")),
        };
        let routed = match self.route(&parsed) {
            Ok(r) => r,
            Err(e) => return write_error(stream, e.status(), &e.to_string()),
        };
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-OH-Volunteer: {}\r\nX-OH-Model: {}\r\nX-OH-Model-Digest: {}\r\nConnection: close\r\n\r\n",
            hex(&routed.volunteer[..8]),
            routed.model_id,
            hex(&self.shared.cfg.model_digest),
        )?;
        stream.flush()?;
        let wait = self.shared.cfg.job_timeout + Duration::from_secs(5);
        loop {
            let ev = routed
                .events
                .recv_timeout(wait)
                .unwrap_or_else(|_| StreamEvent::Failed("volunteer connection lost".into()));
            match ev {
                StreamEvent::Token(t) => {
                    let chunk = serde_json::json!({"object": "chat.completion.chunk", "model": routed.model_id, "choices": [{"index": 0, "delta": {"content": t}}]});
                    write!(stream, "data: {chunk}\n\n")?;
                    stream.flush()?;
                }
                StreamEvent::Done { finish_reason } => {
                    let chunk = serde_json::json!({
                        "object": "chat.completion.chunk",
                        "model": routed.model_id,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                        "oh": {"answered_by": "volunteer", "volunteer": hex(&routed.volunteer[..8]), "model": routed.model_id},
                    });
                    write!(stream, "data: {chunk}\n\ndata: [DONE]\n\n")?;
                    return stream.flush();
                }
                StreamEvent::Failed(why) => {
                    let chunk = serde_json::json!({"error": {"message": why}});
                    write!(stream, "data: {chunk}\n\ndata: [DONE]\n\n")?;
                    return stream.flush();
                }
            }
        }
    }
}

fn set_timeout(s: &mut EncryptedStream<TcpStream>, d: Duration) -> Result<(), String> {
    let d = d.max(Duration::from_millis(1));
    s.get_mut()
        .set_read_timeout(Some(d))
        .and_then(|_| s.get_mut().set_write_timeout(Some(d)))
        .map_err(|e| e.to_string())
}
