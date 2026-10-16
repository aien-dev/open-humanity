//! Teachers: a language model on the volunteer's own machine that writes
//! teaching text for the shared model.
//!
//! `LocalHttpTeacher` talks to an OpenAI-style chat server (the kind local
//! Qwen servers expose) over a minimal HTTP/1.1 client built on
//! `std::net::TcpStream`. It refuses any address that is not loopback unless
//! `allow_remote` is set: the point of teaching mode is that the teacher runs
//! on the volunteer's own machine, so prompts (which carry a hint from the
//! work unit) and the model's raw output never cross a network on the way to
//! the firewall. Only firewalled text is sent on, by the volunteer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Largest response body (and header block) the client will read.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Largest header block, separately capped so a server cannot stream
/// headers forever.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default time allowed for connecting, and for each read or write.
pub const DEFAULT_TEACHER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, thiserror::Error)]
pub enum TeacherError {
    #[error(
        "teacher address {0} is not on this machine (loopback); set allow_remote to permit it"
    )]
    NotLoopback(String),
    #[error("cannot resolve teacher address {0}")]
    BadAddress(String),
    #[error("teacher i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("teacher answered HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("teacher response is malformed: {0}")]
    BadResponse(String),
    #[error("teacher response exceeds the {MAX_RESPONSE_BYTES} byte cap")]
    TooLarge,
}

/// Anything that can write teaching text from a prompt.
pub trait Teacher {
    fn generate(&self, prompt: &str, max_tokens: u32) -> Result<String, TeacherError>;
}

/// A chat model served over HTTP on this machine, for example
/// `aien-serve-http` on `127.0.0.1:18091`.
#[derive(Debug, Clone)]
pub struct LocalHttpTeacher {
    /// `host:port`. A leading `http://` is tolerated.
    pub addr: String,
    /// The exact model id the server lists under `/v1/models`.
    pub model: String,
    /// Permit a teacher on another machine. Off by default; see the module docs.
    pub allow_remote: bool,
    pub timeout: Duration,
}

impl LocalHttpTeacher {
    /// A loopback-only teacher with the default timeout.
    pub fn new(addr: &str, model: &str) -> Self {
        Self {
            addr: addr.to_string(),
            model: model.to_string(),
            allow_remote: false,
            timeout: DEFAULT_TEACHER_TIMEOUT,
        }
    }

    fn client(&self) -> HttpClient {
        HttpClient {
            addr: self.addr.clone(),
            allow_remote: self.allow_remote,
            timeout: self.timeout,
        }
    }
}

impl Teacher for LocalHttpTeacher {
    fn generate(&self, prompt: &str, max_tokens: u32) -> Result<String, TeacherError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "stream": false,
        });
        let body = serde_json::to_vec(&body).expect("a json value always encodes");
        let reply = self
            .client()
            .request("POST", "/v1/chat/completions", Some(&body))?;
        chat_content(&reply)
    }
}

/// Reads `/v1/models` from a loopback server and returns the first model id.
pub fn discover_model(addr: &str) -> Result<String, TeacherError> {
    let client = HttpClient {
        addr: addr.to_string(),
        allow_remote: false,
        timeout: Duration::from_secs(30),
    };
    let reply = client.request("GET", "/v1/models", None)?;
    let value: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|e| TeacherError::BadResponse(e.to_string()))?;
    value["data"][0]["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| TeacherError::BadResponse("no model id under data[0].id".into()))
}

/// Takes `choices[0].message.content`, or `choices[0].text` from servers
/// that answer in the older completions shape.
fn chat_content(body: &[u8]) -> Result<String, TeacherError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| TeacherError::BadResponse(e.to_string()))?;
    let choice = &value["choices"][0];
    choice["message"]["content"]
        .as_str()
        .or_else(|| choice["text"].as_str())
        .map(str::to_string)
        .ok_or_else(|| TeacherError::BadResponse("no text under choices[0].message.content".into()))
}

/// The `error.message` of an OpenAI-style error body, or the body itself.
fn error_message(body: &[u8]) -> String {
    let fallback = || String::from_utf8_lossy(&body[..body.len().min(500)]).into_owned();
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
        .unwrap_or_else(fallback)
}

/// Resolves `addr` and, unless `allow_remote`, requires every resolved
/// address to be loopback (127.0.0.0/8 or ::1).
pub fn resolve_teacher_addr(
    addr: &str,
    allow_remote: bool,
) -> Result<Vec<SocketAddr>, TeacherError> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|_| TeacherError::BadAddress(addr.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(TeacherError::BadAddress(addr.to_string()));
    }
    if !allow_remote && !addrs.iter().all(|a| a.ip().is_loopback()) {
        return Err(TeacherError::NotLoopback(addr.to_string()));
    }
    Ok(addrs)
}

struct HttpClient {
    addr: String,
    allow_remote: bool,
    timeout: Duration,
}

impl HttpClient {
    /// Sends one request with `Connection: close` and returns the body of a
    /// 2xx answer. Other statuses become `TeacherError::Http`.
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, TeacherError> {
        let addr = self.addr.strip_prefix("http://").unwrap_or(&self.addr);
        let addr = addr.trim_end_matches('/');
        let targets = resolve_teacher_addr(addr, self.allow_remote)?;
        let mut last_err = None;
        let mut stream = None;
        for target in &targets {
            match TcpStream::connect_timeout(target, self.timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut stream = match stream {
            Some(s) => s,
            None => return Err(last_err.expect("at least one address was tried").into()),
        };
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let body = body.unwrap_or_default();
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAccept: application/json\r\n"
        );
        if method != "GET" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;

        let (status, reply) = read_response(&mut BufReader::new(stream))?;
        if !(200..300).contains(&status) {
            return Err(TeacherError::Http {
                status,
                message: error_message(&reply),
            });
        }
        Ok(reply)
    }
}

/// Reads one line ending in `\n`, counting it against `budget`.
fn read_line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<String, TeacherError> {
    let mut line = Vec::new();
    let n = r
        .by_ref()
        .take(*budget as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if n > *budget {
        return Err(TeacherError::TooLarge);
    }
    *budget -= n;
    if !line.ends_with(b"\n") {
        return Err(TeacherError::BadResponse(
            "connection closed mid-line".into(),
        ));
    }
    String::from_utf8(line)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|_| TeacherError::BadResponse("header is not UTF-8".into()))
}

/// Parses status line, headers and body. Supports `Content-Length`,
/// `Transfer-Encoding: chunked`, and read-to-close; bodies are capped at
/// `MAX_RESPONSE_BYTES`.
pub(crate) fn read_response<R: BufRead>(r: &mut R) -> Result<(u16, Vec<u8>), TeacherError> {
    let mut header_budget = MAX_HEADER_BYTES;
    let status_line = read_line(r, &mut header_budget)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .filter(|_| status_line.starts_with("HTTP/1."))
        .ok_or_else(|| TeacherError::BadResponse(format!("bad status line {status_line:?}")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let line = read_line(r, &mut header_budget)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(TeacherError::BadResponse(format!("bad header {line:?}")));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let n: u64 = value
                .parse()
                .map_err(|_| TeacherError::BadResponse("bad content-length".into()))?;
            if n > MAX_RESPONSE_BYTES as u64 {
                return Err(TeacherError::TooLarge);
            }
            content_length = Some(n as usize);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"));
        }
    }

    let body = if chunked {
        read_chunked(r)?
    } else if let Some(n) = content_length {
        let mut body = vec![0u8; n];
        r.read_exact(&mut body)?;
        body
    } else {
        let mut body = Vec::new();
        r.take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TeacherError::TooLarge);
        }
        body
    };
    Ok((status, body))
}

fn read_chunked<R: BufRead>(r: &mut R) -> Result<Vec<u8>, TeacherError> {
    let mut body = Vec::new();
    // Chunk-size lines and trailers share one budget per chunk, so memory
    // stays bounded however many chunks arrive.
    loop {
        let mut line_budget = MAX_HEADER_BYTES;
        let line = read_line(r, &mut line_budget)?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16)
            .map_err(|_| TeacherError::BadResponse(format!("bad chunk size {line:?}")))?;
        if size == 0 {
            // Trailers, then the blank line that ends the message.
            while !read_line(r, &mut line_budget)?.is_empty() {}
            return Ok(body);
        }
        if body.len() as u64 + size > MAX_RESPONSE_BYTES as u64 {
            return Err(TeacherError::TooLarge);
        }
        let start = body.len();
        body.resize(start + size as usize, 0);
        r.read_exact(&mut body[start..])?;
        if !read_line(r, &mut line_budget)?.is_empty() {
            return Err(TeacherError::BadResponse(
                "chunk not followed by CRLF".into(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    const REPLY: &str = r#"{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"The model learns from text.","role":"assistant"}}],"model":"fake-model","object":"chat.completion"}"#;

    /// One-shot fake server: reads one request, sends `response`, and hands
    /// back the raw request bytes.
    fn fake_server(response: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = Vec::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                request.extend_from_slice(line.as_bytes());
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            request.extend_from_slice(&body);
            let mut stream = stream;
            stream.write_all(&response).unwrap();
            tx.send(request).unwrap();
        });
        (addr, rx)
    }

    fn with_length(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn chunked(body: &str, pieces: usize) -> Vec<u8> {
        let mut out =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n"
                .to_vec();
        let size = body.len().div_ceil(pieces);
        for piece in body.as_bytes().chunks(size) {
            out.extend_from_slice(format!("{:x};ext=1\r\n", piece.len()).as_bytes());
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\nX-Trailer: yes\r\n\r\n");
        out
    }

    #[test]
    fn test_generate_with_content_length_reply() {
        let (addr, rx) = fake_server(with_length("200 OK", REPLY));
        let teacher = LocalHttpTeacher::new(&addr, "fake-model");
        let text = teacher.generate("Explain \"turings\".", 32).unwrap();
        assert_eq!(text, "The model learns from text.");

        let request = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        let body = &request[request.find("\r\n\r\n").unwrap() + 4..];
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["model"], "fake-model");
        assert_eq!(json["max_tokens"], 32);
        assert_eq!(json["stream"], false);
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"], "Explain \"turings\".");
    }

    #[test]
    fn test_generate_with_chunked_reply() {
        let (addr, _rx) = fake_server(chunked(REPLY, 7));
        let teacher = LocalHttpTeacher::new(&addr, "fake-model");
        assert_eq!(
            teacher.generate("hi", 16).unwrap(),
            "The model learns from text."
        );
    }

    #[test]
    fn test_read_to_close_reply() {
        let raw = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{REPLY}");
        let (status, body) = read_response(&mut Cursor::new(raw.into_bytes())).unwrap();
        assert_eq!(status, 200);
        assert_eq!(chat_content(&body).unwrap(), "The model learns from text.");
    }

    #[test]
    fn test_completions_shape_is_accepted() {
        let body = br#"{"choices":[{"text":"plain completion"}]}"#;
        assert_eq!(chat_content(body).unwrap(), "plain completion");
        assert!(matches!(
            chat_content(br#"{"choices":[]}"#),
            Err(TeacherError::BadResponse(_))
        ));
    }

    #[test]
    fn test_error_reply_carries_the_server_message() {
        let body = r#"{"error":{"message":"model 'qwen' not found"}}"#;
        let (addr, _rx) = fake_server(with_length("404 Not Found", body));
        let err = LocalHttpTeacher::new(&addr, "qwen")
            .generate("hi", 16)
            .unwrap_err();
        assert!(
            matches!(&err, TeacherError::Http { status: 404, message } if message == "model 'qwen' not found"),
            "got {err:?}"
        );
    }

    #[test]
    fn test_discover_model_takes_the_first_id() {
        let body =
            r#"{"object":"list","data":[{"id":"qwen3-test","object":"model"},{"id":"other"}]}"#;
        let (addr, rx) = fake_server(with_length("200 OK", body));
        assert_eq!(discover_model(&addr).unwrap(), "qwen3-test");
        let request = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(request.starts_with("GET /v1/models HTTP/1.1\r\n"));
    }

    #[test]
    fn test_oversize_content_length_is_refused_before_reading() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_RESPONSE_BYTES + 1
        );
        assert!(matches!(
            read_response(&mut Cursor::new(raw.into_bytes())),
            Err(TeacherError::TooLarge)
        ));
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_RESPONSE_BYTES + 1
        );
        assert!(matches!(
            read_response(&mut Cursor::new(raw.into_bytes())),
            Err(TeacherError::TooLarge)
        ));
    }

    #[test]
    fn test_malformed_replies_are_errors() {
        for raw in [
            "garbage\r\n\r\n",
            "HTTP/1.1 200 OK\r\nno-colon-here\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
        ] {
            assert!(
                read_response(&mut Cursor::new(raw.as_bytes().to_vec())).is_err(),
                "accepted {raw:?}"
            );
        }
    }

    #[test]
    fn test_non_loopback_teacher_is_refused_without_connecting() {
        for addr in ["10.0.0.1:18091", "192.168.1.5:80", "[2001:db8::1]:80"] {
            let err = LocalHttpTeacher::new(addr, "m")
                .generate("hi", 1)
                .unwrap_err();
            assert!(
                matches!(err, TeacherError::NotLoopback(_)),
                "{addr}: {err:?}"
            );
            assert!(matches!(
                discover_model(addr),
                Err(TeacherError::NotLoopback(_))
            ));
        }
        assert!(resolve_teacher_addr("10.0.0.1:18091", true).is_ok());
        assert!(resolve_teacher_addr("127.0.0.1:18091", false).is_ok());
        assert!(resolve_teacher_addr("localhost:18091", false).is_ok());
        assert!(resolve_teacher_addr("[::1]:18091", false).is_ok());
        assert!(matches!(
            resolve_teacher_addr("no port here", false),
            Err(TeacherError::BadAddress(_))
        ));
    }

    /// Talks to the real local server. Run by hand:
    /// `cargo test -p oh-core real_local_qwen -- --ignored --nocapture`
    #[test]
    #[ignore = "needs a chat server on 127.0.0.1:18091"]
    fn test_real_local_qwen() {
        let addr = "127.0.0.1:18091";
        let model = discover_model(addr).unwrap();
        eprintln!("model: {model}");
        let text = LocalHttpTeacher::new(addr, &model)
            .generate("Write one short sentence about volunteers.", 32)
            .unwrap();
        eprintln!("text: {text}");
        assert!(!text.trim().is_empty());
    }
}
