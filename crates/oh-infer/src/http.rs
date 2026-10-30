//! Minimal HTTP/1.1 pieces on `std`: request and response heads, bodies by
//! length, chunked or until close, and the `Upgrade: ohinf1` handshake that
//! lets the volunteer connection pass through nginx on port 443.
//!
//! Heads are read one byte at a time, so nothing after the blank line is
//! consumed: after an upgrade, the next byte belongs to the encrypted
//! transport.

use std::io::{self, BufRead, Read, Write};

pub const MAX_HEAD_BYTES: usize = 16 * 1024;
pub const UPGRADE_TOKEN: &str = "ohinf1";

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Reads up to and including the blank line that ends an HTTP head.
pub fn read_head<R: Read>(r: &mut R) -> io::Result<String> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(bad("HTTP head too large"));
        }
        if r.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).map_err(|_| bad("HTTP head is not UTF-8"))
}

#[derive(Debug, Clone, Default)]
pub struct Head {
    /// Request: method. Response: status code as text.
    pub first: String,
    /// Request: path. Response: reason.
    pub second: String,
    /// Lowercased names, trimmed values.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.header(name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }
}

/// Parses a request head (`METHOD PATH HTTP/1.1`) or a response head
/// (`HTTP/1.1 CODE REASON`).
pub fn parse_head(text: &str) -> io::Result<Head> {
    let mut lines = text.split("\r\n");
    let start = lines.next().unwrap_or("");
    let mut parts = start.splitn(3, ' ');
    let (a, b, c) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let mut head = if a.starts_with("HTTP/1.") {
        Head {
            first: b.to_string(),
            second: c.to_string(),
            headers: Vec::new(),
        }
    } else if c.starts_with("HTTP/1.") && !a.is_empty() && b.starts_with('/') {
        Head {
            first: a.to_string(),
            second: b.to_string(),
            headers: Vec::new(),
        }
    } else {
        return Err(bad("malformed HTTP start line"));
    };
    for line in lines.filter(|l| !l.is_empty()) {
        let (n, v) = line
            .split_once(':')
            .ok_or_else(|| bad("malformed header"))?;
        head.headers
            .push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    Ok(head)
}

/// A request with its body (Content-Length only; chunked requests are refused).
pub struct Request {
    pub head: Head,
    pub body: Vec<u8>,
}

pub fn read_request<R: Read>(r: &mut R, max_body: usize) -> io::Result<Request> {
    let head = parse_head(&read_head(r)?)?;
    if head.header("transfer-encoding").is_some() {
        return Err(bad("chunked request bodies are not accepted"));
    }
    let len = match head.header("content-length") {
        Some(v) => v.parse::<usize>().map_err(|_| bad("bad content-length"))?,
        None => 0,
    };
    if len > max_body {
        return Err(bad("request body too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Request { head, body })
}

pub fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Writes a complete response with `Connection: close`.
pub fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        w,
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    )?;
    w.write_all(body)?;
    w.flush()
}

/// A JSON error body in the OpenAI shape.
pub fn write_error<W: Write>(w: &mut W, status: u16, message: &str) -> io::Result<()> {
    let body = serde_json::json!({"error": {"message": message, "code": status}});
    write_response(w, status, "application/json", body.to_string().as_bytes())
}

/// Client side of the upgrade: asks for `path` on `host` and expects 101.
pub fn client_upgrade<S: Read + Write>(s: &mut S, host: &str, path: &str) -> io::Result<()> {
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: {UPGRADE_TOKEN}\r\nConnection: Upgrade\r\nUser-Agent: oh-infer-volunteer/0\r\n\r\n"
    )?;
    s.flush()?;
    let head = parse_head(&read_head(s)?)?;
    if head.first != "101" || !head.has_token("upgrade", UPGRADE_TOKEN) {
        return Err(bad(format!(
            "coordinator answered HTTP {} {} instead of upgrading",
            head.first, head.second
        )));
    }
    Ok(())
}

/// Server side of the upgrade: accepts only `GET <path>` with
/// `Upgrade: ohinf1`, answers 101, and leaves the stream at the first
/// transport byte.
pub fn server_upgrade<S: Read + Write>(s: &mut S, path: &str) -> io::Result<()> {
    let head = parse_head(&read_head(s)?)?;
    if head.first != "GET" || head.second != path || !head.has_token("upgrade", UPGRADE_TOKEN) {
        let _ = write_error(s, 404, "not an Open Humanity inference endpoint");
        return Err(bad("request is not an ohinf1 upgrade"));
    }
    write!(
        s,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {UPGRADE_TOKEN}\r\nConnection: Upgrade\r\n\r\n"
    )?;
    s.flush()
}

/// The body of a response, decoded from chunked, Content-Length or
/// read-until-close framing.
pub enum Body<R> {
    Length(io::Take<R>),
    Chunked { inner: R, left: u64, done: bool },
    Close(R),
}

impl<R: BufRead> Body<R> {
    pub fn new(inner: R, head: &Head) -> io::Result<Self> {
        if head.has_token("transfer-encoding", "chunked") {
            Ok(Body::Chunked {
                inner,
                left: 0,
                done: false,
            })
        } else if let Some(v) = head.header("content-length") {
            let n = v.parse::<u64>().map_err(|_| bad("bad content-length"))?;
            Ok(Body::Length(inner.take(n)))
        } else {
            Ok(Body::Close(inner))
        }
    }
}

impl<R: BufRead> Read for Body<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Length(r) => r.read(buf),
            Body::Close(r) => r.read(buf),
            Body::Chunked { inner, left, done } => {
                if *done {
                    return Ok(0);
                }
                if *left == 0 {
                    let mut line = String::new();
                    if inner.by_ref().take(1024).read_line(&mut line)? == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    let size = line.trim().split(';').next().unwrap_or("");
                    let size = u64::from_str_radix(size, 16).map_err(|_| bad("bad chunk size"))?;
                    if size == 0 {
                        *done = true;
                        return Ok(0);
                    }
                    *left = size;
                }
                let want = buf.len().min(*left as usize);
                let n = inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *left -= n as u64;
                if *left == 0 {
                    let mut crlf = [0u8; 2];
                    inner.read_exact(&mut crlf)?;
                    if &crlf != b"\r\n" {
                        return Err(bad("chunk not followed by CRLF"));
                    }
                }
                Ok(n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn chunked_body_decodes() {
        let head = parse_head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec();
        let mut body = Body::new(BufReader::new(Cursor::new(raw)), &head).unwrap();
        let mut s = String::new();
        body.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello world");
    }

    #[test]
    fn head_reader_stops_at_blank_line() {
        let mut c = Cursor::new(b"GET /x HTTP/1.1\r\nUpgrade: ohinf1\r\n\r\nNEXT".to_vec());
        let head = parse_head(&read_head(&mut c).unwrap()).unwrap();
        assert_eq!(head.first, "GET");
        assert!(head.has_token("upgrade", "ohinf1"));
        let mut rest = String::new();
        c.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "NEXT");
    }
}
