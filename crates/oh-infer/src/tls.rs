//! The volunteer's outbound connection: TLS to the hub (nginx on 443, web
//! PKI roots), or plain TCP only to a loopback address (tests and a local
//! coordinator). The Open Humanity transport runs inside either, so the
//! coordinator key pin holds even if TLS were intercepted.

use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Read and write, for boxing either stream kind.
pub trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

/// A parsed `--coordinator` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Endpoint {
    /// `https://host[:port]/path` or `http://127.0.0.1:port/path`.
    pub fn parse(url: &str) -> Result<Self, String> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!(
                "{url}: use https:// (or http:// to a loopback address)"
            ));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, crate::coordinator::DEFAULT_UPGRADE_PATH),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("{url}: bad port"))?),
            None => (authority, if tls { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(format!("{url}: no host"));
        }
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// Opens the connection. Plain TCP is refused unless every address the
    /// host resolves to is loopback.
    pub fn connect(&self, timeout: Duration) -> Result<Box<dyn Conn>, String> {
        let addrs: Vec<_> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| format!("{}: {e}", self.host))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{} does not resolve", self.host));
        }
        if !self.tls && !addrs.iter().all(|a| a.ip().is_loopback()) {
            return Err(format!(
                "{}: plain http is allowed only to this machine; use https",
                self.host
            ));
        }
        let tcp = TcpStream::connect_timeout(&addrs[0], timeout).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        if !self.tls {
            return Ok(Box::new(tcp));
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(self.host.clone()).map_err(|e| e.to_string())?;
        let conn =
            rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
        Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_refuses_remote_plain_http() {
        let e = Endpoint::parse("https://www.aienos.com/oh/v1/volunteer").unwrap();
        assert_eq!(
            (e.tls, e.port, e.path.as_str()),
            (true, 443, "/oh/v1/volunteer")
        );
        let p = Endpoint::parse("http://127.0.0.1:18096").unwrap();
        assert_eq!(p.path, "/oh/v1/volunteer");
        let remote = Endpoint::parse("http://192.0.2.1:18096/oh/v1/volunteer").unwrap();
        let err = remote.connect(Duration::from_millis(100)).err().unwrap();
        assert!(
            err.contains("plain http is allowed only to this machine"),
            "{err}"
        );
    }
}
