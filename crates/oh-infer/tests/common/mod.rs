//! Shared fixtures: a fake OpenAI-style engine, a tiny model folder with
//! its manifest, a coordinator on loopback ports, and a gateway client.
#![allow(dead_code)]

use beacon_core::Keypair;
use oh_infer::coordinator::{Coordinator, CoordinatorConfig};
use oh_infer::engine::{Engine, EngineError, HttpEngine};
use oh_infer::http::{parse_head, read_head, read_request, Body};
use oh_infer::model::write_manifest;
use oh_infer::protocol::Job;
use oh_infer::volunteer::{run_session, SessionReport, VolunteerConfig, VolunteerError};
use sha2::Digest;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// The fake model's deterministic greedy answer to a request body.
pub fn honest_reply(request: &serde_json::Value) -> String {
    let last = request["messages"]
        .as_array()
        .and_then(|m| m.last())
        .and_then(|m| m["content"].as_str())
        .unwrap_or("");
    format!("Hello from the fake engine. You said: {last}")
}

/// A fake engine on 127.0.0.1. It records every request body it receives
/// and answers with `reply(body)` as an SSE stream, one word per event,
/// using chunked transfer encoding.
pub struct FakeEngine {
    pub addr: String,
    pub seen: Arc<Mutex<Vec<serde_json::Value>>>,
}

pub fn fake_engine(reply: fn(&serde_json::Value) -> String) -> FakeEngine {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = seen.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let Ok(req) = read_request(&mut s, 1 << 20) else {
                continue;
            };
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            rec.lock().unwrap().push(body.clone());
            let text = reply(&body);
            let streaming = body["stream"].as_bool().unwrap_or(false);
            if !streaming {
                let out = serde_json::json!({"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}).to_string();
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", out.len(), out);
                continue;
            }
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
            let mut pieces: Vec<String> = text.split_inclusive(' ').map(str::to_string).collect();
            pieces.push(String::new());
            for (i, p) in pieces.iter().enumerate() {
                let ev = if i + 1 == pieces.len() {
                    format!(
                        "data: {}\n\ndata: [DONE]\n\n",
                        serde_json::json!({"choices": [{"delta": {}, "finish_reason": "stop"}]})
                    )
                } else {
                    format!(
                        "data: {}\n\n",
                        serde_json::json!({"choices": [{"delta": {"content": p}}]})
                    )
                };
                let _ = write!(s, "{:x}\r\n{}\r\n", ev.len(), ev);
            }
            let _ = write!(s, "0\r\n\r\n");
        }
    });
    FakeEngine { addr, seen }
}

/// A temporary model folder: two "weight" files and a manifest.
pub struct ModelDir {
    pub dir: PathBuf,
    pub manifest: PathBuf,
    pub digest: [u8; 32],
    pub name: String,
}

pub fn model_dir(tag: &str) -> ModelDir {
    let dir = std::env::temp_dir().join(format!(
        "oh-infer-test-{tag}-{}-{}",
        std::process::id(),
        rand_u64()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), b"{\"fake\": true}\n").unwrap();
    std::fs::write(dir.join("layers-0.safetensors"), vec![7u8; 4096]).unwrap();
    let name = "fake-model-0001".to_string();
    let manifest_bytes =
        write_manifest(&name, &dir, &["config.json", "layers-0.safetensors"]).unwrap();
    let manifest = dir.join("model.manifest");
    std::fs::write(&manifest, &manifest_bytes).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(&manifest_bytes).into();
    ModelDir {
        dir,
        manifest,
        digest,
        name,
    }
}

impl Drop for ModelDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn rand_u64() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}

/// A coordinator on two fresh loopback ports.
pub struct Running {
    pub coord: Coordinator,
    pub volunteer_addr: String,
    pub api_addr: String,
}

pub fn start(cfg: CoordinatorConfig) -> Running {
    let coord = Coordinator::new(cfg, Keypair::generate()).unwrap();
    let lv = TcpListener::bind("127.0.0.1:0").unwrap();
    let la = TcpListener::bind("127.0.0.1:0").unwrap();
    let volunteer_addr = lv.local_addr().unwrap().to_string();
    let api_addr = la.local_addr().unwrap().to_string();
    let a = coord.clone();
    thread::spawn(move || a.serve_api(la));
    let v = coord.clone();
    thread::spawn(move || v.serve_volunteers(lv));
    Running {
        coord,
        volunteer_addr,
        api_addr,
    }
}

pub fn test_config(model: &ModelDir, approved: &[[u8; 32]]) -> CoordinatorConfig {
    let mut cfg = CoordinatorConfig::new(&model.name, model.digest);
    cfg.approved = approved.iter().copied().collect();
    cfg.routing_enabled = true;
    cfg.ping_interval = Duration::from_millis(200);
    cfg.first_token_timeout = Duration::from_secs(10);
    cfg.job_timeout = Duration::from_secs(20);
    cfg.system_prompt = Some("You are Allen, Drake's public assistant.".into());
    cfg.sampling_seed = Some(1);
    cfg
}

/// An engine wrapper that records each job the volunteer receives.
pub struct Recording<E> {
    pub inner: E,
    pub jobs: Arc<Mutex<Vec<Job>>>,
}

impl<E: Engine> Engine for Recording<E> {
    fn generate(
        &self,
        job: &Job,
        on_token: &mut dyn FnMut(&str) -> Result<(), String>,
    ) -> Result<String, EngineError> {
        self.jobs.lock().unwrap().push(job.clone());
        self.inner.generate(job, on_token)
    }
}

/// Runs an honest volunteer agent session in a thread.
pub fn spawn_volunteer(
    running: &Running,
    model: &ModelDir,
    keypair: Keypair,
    engine_addr: &str,
) -> (
    thread::JoinHandle<Result<SessionReport, VolunteerError>>,
    Arc<Mutex<Vec<Job>>>,
) {
    let jobs = Arc::new(Mutex::new(Vec::new()));
    let engine = Recording {
        inner: HttpEngine::new(engine_addr),
        jobs: jobs.clone(),
    };
    let cfg = VolunteerConfig {
        keypair,
        coordinator_key: running.coord.public_key(),
        host: "127.0.0.1".into(),
        path: "/oh/v1/volunteer".into(),
        model_id: model.name.clone(),
        model_digest: model.digest,
        engine_digest: [0; 32],
        pause_file: None,
    };
    let addr = running.volunteer_addr.clone();
    let h = thread::spawn(move || {
        let s = TcpStream::connect(addr).unwrap();
        run_session(s, &cfg, &engine, &mut |_| {})
    });
    (h, jobs)
}

pub fn wait_healthy(coord: &Coordinator, n: usize) {
    for _ in 0..200 {
        if coord.status().healthy >= n {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("volunteer never became healthy: {:?}", coord.status());
}

/// What the gateway sees for one overflow request.
#[derive(Debug)]
pub struct GatewayReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub text: String,
    pub error: Option<String>,
    pub raw: String,
}

pub fn overflow(api: &str, extra_headers: &str, body: &str) -> GatewayReply {
    let mut s = TcpStream::connect(api).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        s,
        "POST /v1/overflow HTTP/1.1\r\nHost: coordinator\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let head = parse_head(&read_head(&mut s).unwrap()).unwrap();
    let status: u16 = head.first.parse().unwrap();
    let mut raw = String::new();
    Body::new(BufReader::new(s), &head)
        .unwrap()
        .read_to_string(&mut raw)
        .unwrap();
    let mut text = String::new();
    let mut error = None;
    if status == 200 {
        for line in raw.lines() {
            let Some(d) = line.strip_prefix("data: ") else {
                continue;
            };
            if d == "[DONE]" {
                break;
            }
            let v: serde_json::Value = serde_json::from_str(d).unwrap();
            if let Some(t) = v["choices"][0]["delta"]["content"].as_str() {
                text.push_str(t);
            }
            if let Some(e) = v["error"]["message"].as_str() {
                error = Some(e.to_string());
            }
        }
    } else {
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        error = v["error"]["message"].as_str().map(str::to_string);
    }
    GatewayReply {
        status,
        headers: head.headers,
        text,
        error,
        raw,
    }
}

pub fn get(api: &str, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(api).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: c\r\n\r\n").unwrap();
    let head = parse_head(&read_head(&mut s).unwrap()).unwrap();
    let mut raw = String::new();
    Body::new(BufReader::new(s), &head)
        .unwrap()
        .read_to_string(&mut raw)
        .unwrap();
    (head.first.parse().unwrap(), raw)
}

pub fn post(api: &str, path: &str, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(api).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: c\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let head = parse_head(&read_head(&mut s).unwrap()).unwrap();
    let mut raw = String::new();
    Body::new(BufReader::new(s), &head)
        .unwrap()
        .read_to_string(&mut raw)
        .unwrap();
    (head.first.parse().unwrap(), raw)
}

pub fn read_lines_until<R: BufRead>(r: &mut R, needle: &str) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).unwrap() == 0 {
            panic!("stream ended before {needle:?}");
        }
        if line.contains(needle) {
            return line;
        }
    }
}

pub fn path_str(p: &Path) -> String {
    p.display().to_string()
}
