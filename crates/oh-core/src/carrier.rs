//! Bounded typed frames that carry one microjob over an [`EncryptedStream`]
//! (Aienet-0 P0 job path, aien-protocols-mv `specs/aienet/jobpath`).
//!
//! A frame is `tag[1] || len[4, big endian] || body`, written and flushed as
//! one unit (one sealed record when the stream is encrypted). The carrier
//! treats the MJB1 bundle and the MJR1 receipt as opaque bytes: it checks the
//! tag, the length bound of that tag and nothing else, so the transport does
//! not depend on the wire format it carries. The receiver refuses an unknown
//! tag or an out-of-bound length before reading the body.
//!
//! [`EncryptedStream`]: crate::transport::EncryptedStream

use std::io::{self, Read, Write};

/// Frame tags.
pub mod tag {
    /// Coordinator to volunteer: one submitter-signed job bundle.
    pub const BUNDLE: u8 = 1;
    /// Volunteer to coordinator: one signed receipt.
    pub const RECEIPT: u8 = 2;
    /// Either way: a refusal code and reason, UTF-8.
    pub const REFUSAL: u8 = 3;
}

/// Largest bundle body: a 109-byte bundle head, a 256-byte payload and the
/// largest MJB1 document (192 + 64 x 448 bytes).
pub const MAX_BUNDLE: usize = 109 + 256 + 192 + 64 * 448;
/// A receipt body is exactly one MJR1 record.
pub const RECEIPT_LEN: usize = 404;
/// Largest refusal body.
pub const MAX_REFUSAL: usize = 512;

/// One carrier frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Bundle(Vec<u8>),
    Receipt(Vec<u8>),
    Refusal(String),
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn bound(t: u8) -> io::Result<(usize, usize)> {
    match t {
        tag::BUNDLE => Ok((1, MAX_BUNDLE)),
        tag::RECEIPT => Ok((RECEIPT_LEN, RECEIPT_LEN)),
        tag::REFUSAL => Ok((1, MAX_REFUSAL)),
        _ => Err(invalid("carrier frame has an unknown tag")),
    }
}

/// Write one frame and flush it.
pub fn send_frame<W: Write>(w: &mut W, f: &Frame) -> io::Result<()> {
    let (t, body): (u8, &[u8]) = match f {
        Frame::Bundle(b) => (tag::BUNDLE, b),
        Frame::Receipt(b) => (tag::RECEIPT, b),
        Frame::Refusal(s) => (tag::REFUSAL, s.as_bytes()),
    };
    let (min, max) = bound(t)?;
    if body.len() < min || body.len() > max {
        return Err(invalid("carrier frame body is outside its bound"));
    }
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(t);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

/// Read one frame. Refuses an unknown tag or out-of-bound length before
/// reading the body.
pub fn recv_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head)?;
    let (min, max) = bound(head[0])?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    // AN0-GUARD carrier-bound
    if len < min || len > max {
        return Err(invalid("carrier frame body is outside its bound"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(match head[0] {
        tag::BUNDLE => Frame::Bundle(body),
        tag::RECEIPT => Frame::Receipt(body),
        _ => Frame::Refusal(
            String::from_utf8(body).map_err(|_| invalid("carrier refusal is not UTF-8"))?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{coordinator_handshake_pinned, volunteer_handshake, CoordinatorPin};
    use beacon_core::Keypair;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn round_trip(f: Frame) -> Frame {
        let mut buf = Vec::new();
        send_frame(&mut buf, &f).unwrap();
        recv_frame(&mut buf.as_slice()).unwrap()
    }

    #[test]
    fn frames_round_trip() {
        for f in [
            Frame::Bundle(vec![7; MAX_BUNDLE]),
            Frame::Receipt(vec![1; RECEIPT_LEN]),
            Frame::Refusal("AN0_REPLAY seen".into()),
        ] {
            assert_eq!(round_trip(f.clone()), f);
        }
    }

    #[test]
    fn out_of_bound_frames_are_not_sent() {
        let mut buf = Vec::new();
        assert!(send_frame(&mut buf, &Frame::Bundle(vec![0; MAX_BUNDLE + 1])).is_err());
        assert!(send_frame(&mut buf, &Frame::Receipt(vec![0; RECEIPT_LEN - 1])).is_err());
        assert!(send_frame(&mut buf, &Frame::Refusal(String::new())).is_err());
        assert!(buf.is_empty());
    }

    #[test]
    fn unknown_tag_and_oversize_length_are_refused_before_the_body() {
        let unknown = [9u8, 0, 0, 0, 1, 0];
        assert!(recv_frame(&mut &unknown[..]).is_err());
        let mut huge = vec![tag::BUNDLE];
        huge.extend_from_slice(&((MAX_BUNDLE + 1) as u32).to_be_bytes());
        let e = recv_frame(&mut huge.as_slice()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "AN0_SEMANTIC carrier-bound");
        let mut short = vec![tag::RECEIPT];
        short.extend_from_slice(&403u32.to_be_bytes());
        assert!(recv_frame(&mut short.as_slice()).is_err());
    }

    #[test]
    fn bundle_and_receipt_cross_a_pinned_encrypted_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let coord = Keypair::generate();
        let vol = Keypair::generate();
        let (coord_pub, vol_pub) = (coord.pubkey_bytes(), vol.pubkey_bytes());
        let h = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut c = coordinator_handshake_pinned(s, &coord, vol_pub).unwrap();
            send_frame(&mut c, &Frame::Bundle(b"AN0B bundle".to_vec())).unwrap();
            recv_frame(&mut c).unwrap()
        });
        let s = TcpStream::connect(addr).unwrap();
        let mut v = volunteer_handshake(s, &vol, CoordinatorPin::Key(coord_pub)).unwrap();
        assert_eq!(
            recv_frame(&mut v).unwrap(),
            Frame::Bundle(b"AN0B bundle".to_vec())
        );
        send_frame(&mut v, &Frame::Receipt(vec![0x4D; RECEIPT_LEN])).unwrap();
        assert_eq!(h.join().unwrap(), Frame::Receipt(vec![0x4D; RECEIPT_LEN]));
    }
}
