//! The volunteer's local engine: an OpenAI-style chat server on this
//! machine (the SI engine, `aien-serve-http`, on 127.0.0.1:18100 by
//! default). Only loopback addresses are accepted, so the job text goes no
//! further than this machine on its way to the engine.

use crate::http::{parse_head, read_head, Body};
use crate::protocol::{Job, MAX_OUTPUT_BYTES};
use oh_core::resolve_teacher_addr;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const DEFAULT_ENGINE_ADDR: &str = "127.0.0.1:18100";

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine address {0} is not loopback or does not resolve")]
    Address(String),
    #[error("engine i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("engine answered HTTP {0}")]
    Http(String),
    #[error("engine reply is malformed: {0}")]
    Malformed(String),
    #[error("engine reply exceeds {MAX_OUTPUT_BYTES} bytes")]
    TooLarge,
    #[error("forwarding a token failed: {0}")]
    Forward(String),
}

/// Writes the reply to a job, calling `on_token` for each piece as it
/// arrives. Returns the finish reason ("stop" or "length").
pub trait Engine {
    fn generate(
        &self,
        job: &Job,
        on_token: &mut dyn FnMut(&str) -> Result<(), String>,
    ) -> Result<String, EngineError>;
}

#[derive(Debug, Clone)]
pub struct HttpEngine {
    pub addr: String,
    pub timeout: Duration,
}

impl HttpEngine {
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.trim_start_matches("http://").to_string(),
            timeout: Duration::from_secs(300),
        }
    }
}

/// The request body every engine receives: greedy decoding with the job's
/// seed, streamed.
pub fn request_body(job: &Job) -> serde_json::Value {
    let messages: Vec<serde_json::Value> = job
        .messages
        .iter()
        .map(|m| serde_json::json!({"role": m.role.as_str(), "content": m.content}))
        .collect();
    serde_json::json!({
        "model": job.model_id,
        "messages": messages,
        "max_tokens": job.max_tokens,
        "temperature": 0,
        "top_p": 1,
        "seed": job.seed,
        "stream": true,
    })
}

impl Engine for HttpEngine {
    fn generate(
        &self,
        job: &Job,
        on_token: &mut dyn FnMut(&str) -> Result<(), String>,
    ) -> Result<String, EngineError> {
        let addrs = resolve_teacher_addr(&self.addr, false)
            .map_err(|_| EngineError::Address(self.addr.clone()))?;
        let mut s = TcpStream::connect_timeout(&addrs[0], self.timeout)?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        let body = request_body(job).to_string();
        write!(
            s,
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            body.len(),
            body
        )?;
        s.flush()?;
        let head = parse_head(&read_head(&mut s)?)?;
        if head.first != "200" {
            return Err(EngineError::Http(format!("{} {}", head.first, head.second)));
        }
        let is_sse = head
            .header("content-type")
            .is_some_and(|v| v.starts_with("text/event-stream"));
        let body = Body::new(BufReader::new(s), &head)?;
        if is_sse {
            read_sse(BufReader::new(body), on_token)
        } else {
            read_json(body, on_token)
        }
    }
}

fn read_sse<R: BufRead>(
    mut r: R,
    on_token: &mut dyn FnMut(&str) -> Result<(), String>,
) -> Result<String, EngineError> {
    let mut total = 0usize;
    let mut finish = String::from("stop");
    let mut line = String::new();
    loop {
        line.clear();
        if r.by_ref()
            .take(MAX_OUTPUT_BYTES as u64 + 4096)
            .read_line(&mut line)?
            == 0
        {
            return Ok(finish);
        }
        let Some(data) = line.trim_end().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data == "[DONE]" {
            return Ok(finish);
        }
        let v: serde_json::Value =
            serde_json::from_str(data).map_err(|e| EngineError::Malformed(e.to_string()))?;
        let choice = &v["choices"][0];
        if let Some(text) = choice["delta"]["content"].as_str() {
            total += text.len();
            if total > MAX_OUTPUT_BYTES {
                return Err(EngineError::TooLarge);
            }
            if !text.is_empty() {
                on_token(text).map_err(EngineError::Forward)?;
            }
        }
        if let Some(f) = choice["finish_reason"].as_str() {
            finish = f.to_string();
        }
    }
}

fn read_json<R: Read>(
    r: R,
    on_token: &mut dyn FnMut(&str) -> Result<(), String>,
) -> Result<String, EngineError> {
    let mut body = Vec::new();
    r.take(MAX_OUTPUT_BYTES as u64 * 2 + 1)
        .read_to_end(&mut body)?;
    let v: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| EngineError::Malformed(e.to_string()))?;
    let choice = &v["choices"][0];
    let text = choice["message"]["content"]
        .as_str()
        .ok_or_else(|| EngineError::Malformed("no choices[0].message.content".into()))?;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err(EngineError::TooLarge);
    }
    if !text.is_empty() {
        on_token(text).map_err(EngineError::Forward)?;
    }
    Ok(choice["finish_reason"]
        .as_str()
        .unwrap_or("stop")
        .to_string())
}
