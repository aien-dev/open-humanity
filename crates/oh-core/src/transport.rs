//! Encrypted transport between the coordinator and a volunteer.
//!
//! Handshake (one message each way, volunteer first), each hello is
//! `version[8] || identity[32] || ephemeral[32] || sig[64]`:
//!
//! 1. Volunteer: a fresh X25519 key, signed with its Ed25519 identity over
//!    `VOLUNTEER_CONTEXT || identity || ephemeral`.
//! 2. Coordinator: a fresh X25519 key, signed with its Ed25519 identity over
//!    `COORDINATOR_CONTEXT || volunteer hello || identity || ephemeral`, so
//!    the signature is bound to this session and cannot be replayed into
//!    another.
//!
//! The volunteer checks the coordinator identity against a pinned key (or
//! accepts it on first use when the caller allows that). Both sides derive
//! one key per direction with BLAKE3 `derive_key` from the X25519 shared
//! secret and a hash of both hellos.
//!
//! After the handshake every byte goes in sealed records:
//! `len[4, big endian] || ChaCha20-Poly1305(padded)`, with the length
//! header as associated data. `padded` is `data_len[4, big endian] || data ||
//! zero bytes`, grown to a size bucket (the next power of two, at least
//! 1 KiB, at most 64 MiB), so the record length on the wire only tells an
//! observer which bucket the data fell in. The receiver refuses a record
//! whose length field, bucket size or padding bytes are not exactly what an
//! honest sender produces. The nonce is the record number in this
//! direction (4 zero bytes then the 64-bit little-endian counter); it is
//! never sent, never reused, and the receiver only accepts the next number,
//! so a replayed, dropped or reordered record fails to open and closes the
//! stream. All primitives come from beacon-core (x25519-dalek,
//! chacha20poly1305) and blake3; nothing here is new cryptography.

use beacon_core::{verify_signature, EphemeralKeyAgreement, Keypair, SessionCipher};
use std::io::{self, Read, Write};

/// Protocol tag at the start of each hello.
pub const TRANSPORT_VERSION: &[u8; 8] = b"OHSEC002";
const VOLUNTEER_CONTEXT: &[u8] = b"open-humanity transport v1: volunteer hello";
const COORDINATOR_CONTEXT: &[u8] = b"open-humanity transport v1: coordinator hello";
const KEY_V2C: &str = "open-humanity transport v1 2026-10-16 volunteer to coordinator";
const KEY_C2V: &str = "open-humanity transport v1 2026-10-16 coordinator to volunteer";
const HELLO_LEN: usize = 8 + 32 + 32 + 64;
const TAG_LEN: usize = 16;
/// Smallest padded record plaintext (1 KiB).
pub const MIN_PADDED_RECORD: usize = 1024;
/// Largest padded record plaintext (64 MiB).
pub const MAX_PADDED_RECORD: usize = 1 << 26;
/// Bytes of the inner length field at the start of each padded record.
const PAD_HEADER: usize = 4;
/// Most data one record carries; longer flushes are split.
pub const MAX_RECORD_DATA: usize = MAX_PADDED_RECORD - PAD_HEADER;

/// Size of the padded plaintext that carries `data_len` bytes: the next
/// power of two that fits the data and its length field, at least
/// `MIN_PADDED_RECORD`. `data_len` must be at most `MAX_RECORD_DATA`.
pub fn padded_size(data_len: usize) -> usize {
    (data_len + PAD_HEADER)
        .next_power_of_two()
        .max(MIN_PADDED_RECORD)
}

fn pad(data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() <= MAX_RECORD_DATA);
    let mut out = vec![0u8; padded_size(data.len())];
    out[..PAD_HEADER].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out[PAD_HEADER..PAD_HEADER + data.len()].copy_from_slice(data);
    out
}

/// Strips the padding from an opened record. `None` unless the length
/// field, the bucket size and the all-zero padding are exactly what `pad`
/// produces.
fn unpad(mut padded: Vec<u8>) -> Option<Vec<u8>> {
    if padded.len() < PAD_HEADER {
        return None;
    }
    let len = u32::from_be_bytes(padded[..PAD_HEADER].try_into().ok()?) as usize;
    if len > padded.len() - PAD_HEADER || padded.len() != padded_size(len) {
        return None;
    }
    if padded[PAD_HEADER + len..].iter().any(|&b| b != 0) {
        return None;
    }
    padded.truncate(PAD_HEADER + len);
    padded.drain(..PAD_HEADER);
    Some(padded)
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("peer does not speak this transport version")]
    BadVersion,
    #[error("peer's hello signature does not verify")]
    BadSignature,
    #[error("key agreement failed")]
    KeyAgreement,
    #[error("coordinator key {got} is not the pinned key {expected}")]
    WrongCoordinator { expected: String, got: String },
    #[error("volunteer key {got} is not the pinned key {expected}")]
    WrongVolunteer { expected: String, got: String },
}

/// Which coordinator identity a volunteer accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorPin {
    /// Only this Ed25519 public key.
    Key([u8; 32]),
    /// Whatever key the coordinator presents. An attacker in the middle of
    /// the first connection can present their own; the caller should warn.
    TrustFirstUse,
}

struct Hello {
    bytes: [u8; HELLO_LEN],
}

impl Hello {
    fn new(identity: &Keypair, ephemeral: &[u8; 32], signed_prefix: &[u8]) -> Self {
        let mut bytes = [0u8; HELLO_LEN];
        bytes[..8].copy_from_slice(TRANSPORT_VERSION);
        bytes[8..40].copy_from_slice(&identity.pubkey_bytes());
        bytes[40..72].copy_from_slice(ephemeral);
        let mut msg = signed_prefix.to_vec();
        msg.extend_from_slice(&bytes[8..72]);
        bytes[72..].copy_from_slice(&identity.sign(&msg));
        Self { bytes }
    }

    fn read<R: Read>(r: &mut R) -> Result<Self, TransportError> {
        let mut bytes = [0u8; HELLO_LEN];
        r.read_exact(&mut bytes)?;
        if &bytes[..8] != TRANSPORT_VERSION {
            return Err(TransportError::BadVersion);
        }
        Ok(Self { bytes })
    }

    fn identity(&self) -> [u8; 32] {
        self.bytes[8..40].try_into().expect("32 bytes")
    }

    fn ephemeral(&self) -> [u8; 32] {
        self.bytes[40..72].try_into().expect("32 bytes")
    }

    fn verify(&self, signed_prefix: &[u8]) -> Result<(), TransportError> {
        let mut msg = signed_prefix.to_vec();
        msg.extend_from_slice(&self.bytes[8..72]);
        let sig: [u8; 64] = self.bytes[72..].try_into().expect("64 bytes");
        verify_signature(&self.identity(), &msg, &sig).map_err(|_| TransportError::BadSignature)
    }
}

fn coordinator_prefix(volunteer_hello: &Hello) -> Vec<u8> {
    let mut p = COORDINATOR_CONTEXT.to_vec();
    p.extend_from_slice(&volunteer_hello.bytes);
    p
}

/// (volunteer to coordinator key, coordinator to volunteer key).
fn session_keys(shared: &[u8; 32], v: &Hello, c: &Hello) -> ([u8; 32], [u8; 32]) {
    let mut transcript = blake3::Hasher::new();
    transcript.update(&v.bytes);
    transcript.update(&c.bytes);
    let mut material = shared.to_vec();
    material.extend_from_slice(transcript.finalize().as_bytes());
    (
        blake3::derive_key(KEY_V2C, &material),
        blake3::derive_key(KEY_C2V, &material),
    )
}

/// Volunteer side of the handshake. Sends nothing after the hello unless
/// the coordinator's signature verifies and its key passes `pin`.
pub fn volunteer_handshake<S: Read + Write>(
    mut stream: S,
    identity: &Keypair,
    pin: CoordinatorPin,
) -> Result<EncryptedStream<S>, TransportError> {
    let eph = EphemeralKeyAgreement::generate();
    let mine = Hello::new(identity, &eph.public_bytes(), VOLUNTEER_CONTEXT);
    stream.write_all(&mine.bytes)?;
    stream.flush()?;
    let theirs = Hello::read(&mut stream)?;
    theirs.verify(&coordinator_prefix(&mine))?;
    if let CoordinatorPin::Key(expected) = pin {
        // AN0-GUARD coordinator-pin
        if theirs.identity() != expected {
            return Err(TransportError::WrongCoordinator {
                expected: hex(&expected),
                got: hex(&theirs.identity()),
            });
        }
    }
    let shared = eph
        .agree(&theirs.ephemeral())
        .map_err(|_| TransportError::KeyAgreement)?;
    let (v2c, c2v) = session_keys(&shared, &mine, &theirs);
    Ok(EncryptedStream::new(stream, &v2c, &c2v, theirs.identity()))
}

/// Coordinator side of the handshake. Accepts any volunteer identity; the
/// caller reads it from [`EncryptedStream::peer_identity`].
pub fn coordinator_handshake<S: Read + Write>(
    stream: S,
    identity: &Keypair,
) -> Result<EncryptedStream<S>, TransportError> {
    coordinator_handshake_inner(stream, identity, None)
}

/// Coordinator side of the handshake that admits only the volunteer
/// `expected`. A volunteer with any other key is refused after its hello
/// verifies and before the coordinator sends anything.
pub fn coordinator_handshake_pinned<S: Read + Write>(
    stream: S,
    identity: &Keypair,
    expected: [u8; 32],
) -> Result<EncryptedStream<S>, TransportError> {
    coordinator_handshake_inner(stream, identity, Some(expected))
}

fn coordinator_handshake_inner<S: Read + Write>(
    mut stream: S,
    identity: &Keypair,
    pin: Option<[u8; 32]>,
) -> Result<EncryptedStream<S>, TransportError> {
    let theirs = Hello::read(&mut stream)?;
    theirs.verify(VOLUNTEER_CONTEXT)?;
    if let Some(expected) = pin {
        // AN0-GUARD volunteer-pin
        if theirs.identity() != expected {
            return Err(TransportError::WrongVolunteer {
                expected: hex(&expected),
                got: hex(&theirs.identity()),
            });
        }
    }
    let eph = EphemeralKeyAgreement::generate();
    let mine = Hello::new(identity, &eph.public_bytes(), &coordinator_prefix(&theirs));
    stream.write_all(&mine.bytes)?;
    stream.flush()?;
    let shared = eph
        .agree(&theirs.ephemeral())
        .map_err(|_| TransportError::KeyAgreement)?;
    let (v2c, c2v) = session_keys(&shared, &theirs, &mine);
    Ok(EncryptedStream::new(stream, &c2v, &v2c, theirs.identity()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// A stream whose bytes travel in sealed records. Writes are buffered and
/// sealed on `flush`; data written but not flushed is not sent.
pub struct EncryptedStream<S> {
    inner: S,
    send: SessionCipher,
    recv: SessionCipher,
    send_counter: u64,
    recv_counter: u64,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    peer_identity: [u8; 32],
    /// Set after a record fails to open; every later read fails.
    broken: bool,
}

impl<S> EncryptedStream<S> {
    fn new(inner: S, send_key: &[u8; 32], recv_key: &[u8; 32], peer: [u8; 32]) -> Self {
        Self {
            inner,
            send: SessionCipher::new(send_key),
            recv: SessionCipher::new(recv_key),
            send_counter: 0,
            recv_counter: 0,
            write_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            peer_identity: peer,
            broken: false,
        }
    }

    /// The Ed25519 identity the peer proved in the handshake.
    pub fn peer_identity(&self) -> [u8; 32] {
        self.peer_identity
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The raw stream underneath. Bytes written or read here bypass the
    /// encryption; meant for tests and socket settings.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl<S: Read> EncryptedStream<S> {
    /// Reads and opens the next record. `Ok(false)` on a clean end of stream
    /// between records.
    fn fill(&mut self) -> io::Result<bool> {
        let mut header = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match self.inner.read(&mut header[got..]) {
                Ok(0) if got == 0 => return Ok(false),
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let len = u32::from_be_bytes(header) as usize;
        if !(MIN_PADDED_RECORD + TAG_LEN..=MAX_PADDED_RECORD + TAG_LEN).contains(&len) {
            self.broken = true;
            return Err(invalid("encrypted record has an impossible length"));
        }
        let mut sealed = vec![0u8; len];
        self.inner.read_exact(&mut sealed)?;
        match self.recv.open(&nonce(self.recv_counter), &header, &sealed) {
            Ok(padded) => {
                self.recv_counter += 1;
                match unpad(padded) {
                    Some(plain) => {
                        self.read_buf = plain;
                        self.read_pos = 0;
                        Ok(true)
                    }
                    None => {
                        self.broken = true;
                        Err(invalid("encrypted record has malformed padding"))
                    }
                }
            }
            Err(_) => {
                self.broken = true;
                Err(invalid(
                    "encrypted record failed to open: tampered, replayed or out of order",
                ))
            }
        }
    }
}

impl<S: Read> Read for EncryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.read_pos == self.read_buf.len() {
            if self.broken {
                return Err(invalid("encrypted stream is closed after a bad record"));
            }
            if !self.fill()? {
                return Ok(0);
            }
        }
        let n = buf.len().min(self.read_buf.len() - self.read_pos);
        buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl<S: Write> EncryptedStream<S> {
    /// Seals one already padded plaintext as the next record and writes it.
    fn seal_record(&mut self, padded: &[u8]) -> io::Result<()> {
        if self.send_counter == u64::MAX {
            return Err(io::Error::other("record counter exhausted"));
        }
        let header = ((padded.len() + TAG_LEN) as u32).to_be_bytes();
        let sealed = self
            .send
            .seal(&nonce(self.send_counter), &header, padded)
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.send_counter += 1;
        self.inner.write_all(&header)?;
        self.inner.write_all(&sealed)
    }
}

impl<S: Write> Write for EncryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Seals everything written since the last flush and sends it, padded
    /// to size buckets, in records of at most `MAX_RECORD_DATA` bytes of
    /// data each.
    fn flush(&mut self) -> io::Result<()> {
        let pending = std::mem::take(&mut self.write_buf);
        for chunk in pending.chunks(MAX_RECORD_DATA) {
            self.seal_record(&pad(chunk))?;
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (b, _) = listener.accept().unwrap();
        (a, b)
    }

    /// (volunteer side, coordinator side, coordinator identity).
    fn session(
        pin: impl FnOnce(&Keypair) -> CoordinatorPin,
    ) -> (
        Result<EncryptedStream<TcpStream>, TransportError>,
        Result<EncryptedStream<TcpStream>, TransportError>,
    ) {
        let (v, c) = tcp_pair();
        let coord = Keypair::generate();
        let pin = pin(&coord);
        let handle = thread::spawn(move || coordinator_handshake(c, &coord));
        let vol = volunteer_handshake(v, &Keypair::generate(), pin);
        (vol, handle.join().unwrap())
    }

    fn pinned() -> (EncryptedStream<TcpStream>, EncryptedStream<TcpStream>) {
        let (v, c) = session(|k| CoordinatorPin::Key(k.pubkey_bytes()));
        (v.unwrap(), c.unwrap())
    }

    /// Reads one raw record (header and sealed bytes) off the wire.
    fn raw_record(s: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 4];
        s.read_exact(&mut header).unwrap();
        let mut rec = header.to_vec();
        let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
        s.read_exact(&mut body).unwrap();
        rec.extend_from_slice(&body);
        rec
    }

    fn send_frame(s: &mut EncryptedStream<TcpStream>, msg: &[u8]) {
        s.write_all(msg).unwrap();
        s.flush().unwrap();
    }

    #[test]
    fn test_round_trip_both_directions() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"update from the volunteer");
        let mut got = [0u8; 25];
        c.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"update from the volunteer");
        send_frame(&mut c, b"receipt");
        let mut got = [0u8; 7];
        v.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"receipt");
        assert_eq!(c.peer_identity().len(), 32);
        // Frames of the wire format pass through unchanged.
        let unit = crate::wire::BaseModel {
            dim: 2,
            params: vec![1.0, 2.0],
        };
        crate::wire::send(&mut c, &unit).unwrap();
        let back: crate::wire::BaseModel = crate::wire::recv(&mut v).unwrap();
        assert_eq!(back.params, unit.params);
    }

    #[test]
    fn test_ciphertext_on_the_wire_is_not_the_plaintext() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"secret shard bytes");
        let rec = raw_record(c.get_mut());
        assert!(!rec.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn test_tampered_ciphertext_is_rejected() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"hello coordinator");
        let mut rec = raw_record(c.get_mut());
        rec[10] ^= 0x01;
        v.get_mut().write_all(&rec).unwrap();
        let mut buf = [0u8; 17];
        let err = c.read_exact(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // The stream stays closed afterwards.
        assert!(c.read(&mut buf).is_err());
    }

    #[test]
    fn test_tampered_length_header_is_rejected() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"hello coordinator");
        let mut rec = raw_record(c.get_mut());
        // Shorter length, same bytes: the header is authenticated.
        let len = u32::from_be_bytes(rec[..4].try_into().unwrap()) - 1;
        rec[..4].copy_from_slice(&len.to_be_bytes());
        v.get_mut().write_all(&rec).unwrap();
        let mut buf = [0u8; 4];
        assert!(c.read_exact(&mut buf).is_err());
    }

    #[test]
    fn test_replayed_record_is_rejected() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"one");
        let rec = raw_record(c.get_mut());
        v.get_mut().write_all(&rec).unwrap();
        let mut buf = [0u8; 3];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"one");
        v.get_mut().write_all(&rec).unwrap();
        let err = c.read_exact(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_reordered_records_are_rejected() {
        let (mut v, mut c) = pinned();
        send_frame(&mut v, b"first");
        send_frame(&mut v, b"second");
        let r1 = raw_record(c.get_mut());
        let r2 = raw_record(c.get_mut());
        v.get_mut().write_all(&r2).unwrap();
        v.get_mut().write_all(&r1).unwrap();
        let mut buf = [0u8; 6];
        assert!(c.read_exact(&mut buf).is_err());
    }

    #[test]
    fn test_record_from_the_other_direction_is_rejected() {
        // Each direction has its own key: a record the coordinator sent
        // cannot be reflected back to it.
        let (mut v, mut c) = pinned();
        send_frame(&mut c, b"receipt");
        let rec = raw_record(v.get_mut());
        v.get_mut().write_all(&rec).unwrap();
        let mut buf = [0u8; 7];
        assert!(c.read_exact(&mut buf).is_err());
    }

    #[test]
    fn test_padded_size_buckets() {
        assert_eq!(padded_size(0), 1024);
        assert_eq!(padded_size(1020), 1024);
        assert_eq!(padded_size(1021), 2048);
        assert_eq!(padded_size(5000), 8192);
        assert_eq!(padded_size(MAX_RECORD_DATA), MAX_PADDED_RECORD);
        assert!(MAX_PADDED_RECORD <= crate::wire::MAX_FRAME_BYTES as usize);
    }

    #[test]
    fn test_messages_in_one_bucket_have_equal_ciphertext_length() {
        let (mut v, mut c) = pinned();
        // A short receipt and a 900-byte update both land in the 1 KiB
        // bucket; 3000 and 4000 bytes both land in 4 KiB.
        let mut lens = Vec::new();
        for size in [7usize, 900, 3000, 4000] {
            send_frame(&mut v, &vec![0xab; size]);
            lens.push(raw_record(c.get_mut()).len());
        }
        assert_eq!(lens[0], lens[1]);
        assert_eq!(lens[0], 4 + 1024 + TAG_LEN);
        assert_eq!(lens[2], lens[3]);
        assert_eq!(lens[2], 4 + 4096 + TAG_LEN);
    }

    #[test]
    fn test_padded_round_trip_is_exact() {
        let (mut v, mut c) = pinned();
        let sizes = [1usize, 1019, 1020, 1021, 4092, 4093, 70_000];
        let handle = thread::spawn(move || {
            for (i, size) in sizes.iter().enumerate() {
                let msg: Vec<u8> = (0..*size).map(|j| (i * 31 + j) as u8).collect();
                send_frame(&mut v, &msg);
            }
            v
        });
        for (i, size) in sizes.iter().enumerate() {
            let want: Vec<u8> = (0..*size).map(|j| (i * 31 + j) as u8).collect();
            let mut got = vec![0u8; *size];
            c.read_exact(&mut got).unwrap();
            assert_eq!(got, want);
        }
        // Nothing but the data comes out: once the sender is gone the next
        // read sees a clean end of stream, no padding bytes.
        drop(handle.join().unwrap());
        let mut rest = Vec::new();
        assert_eq!(c.read_to_end(&mut rest).unwrap(), 0);
    }

    /// Seals `padded` as-is (no padding added) as the volunteer's next
    /// record, so a test can send what an honest sender never would.
    fn send_raw_padded(v: &mut EncryptedStream<TcpStream>, padded: &[u8]) {
        v.seal_record(padded).unwrap();
        v.get_mut().flush().unwrap();
    }

    fn assert_padding_rejected(padded: Vec<u8>) {
        let (mut v, mut c) = pinned();
        send_raw_padded(&mut v, &padded);
        let mut buf = [0u8; 1];
        let err = c.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("padding"), "{err}");
        assert!(c.read(&mut buf).is_err(), "stream stays closed");
    }

    #[test]
    fn test_malformed_padding_is_rejected() {
        // Control: the honest encoding opens.
        let (mut v, mut c) = pinned();
        send_raw_padded(&mut v, &pad(b"ok"));
        let mut buf = [0u8; 2];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");

        // Length field claims more data than the record holds.
        let mut p = pad(b"hello");
        p[..4].copy_from_slice(&2000u32.to_be_bytes());
        assert_padding_rejected(p);

        // A padding byte is not zero.
        let mut p = pad(b"hello");
        p[100] = 1;
        assert_padding_rejected(p);

        // Valid layout, but a bigger bucket than the data needs.
        let mut p = vec![0u8; 2048];
        p[..4].copy_from_slice(&5u32.to_be_bytes());
        p[4..9].copy_from_slice(b"hello");
        assert_padding_rejected(p);
    }

    #[test]
    fn test_record_below_the_smallest_bucket_is_rejected() {
        let (mut v, mut c) = pinned();
        send_raw_padded(&mut v, b"\0\0\0\x02hi");
        let mut buf = [0u8; 2];
        let err = c.read_exact(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_wrong_pinned_key_is_refused() {
        let other = Keypair::generate().pubkey_bytes();
        let (v, _c) = session(|_| CoordinatorPin::Key(other));
        assert!(v.is_err(), "AN0_SEMANTIC coordinator-pin");
        assert!(matches!(v, Err(TransportError::WrongCoordinator { .. })));
    }

    #[test]
    fn test_trust_first_use_accepts_and_reports_the_key() {
        let (v, c) = session(|_| CoordinatorPin::TrustFirstUse);
        let (v, _c) = (v.unwrap(), c.unwrap());
        assert_ne!(v.peer_identity(), [0u8; 32]);
    }

    /// (volunteer result, coordinator result, volunteer identity) with the
    /// coordinator pinning `pin(volunteer identity)`.
    fn pinned_volunteer_session(
        pin: impl FnOnce(&Keypair) -> [u8; 32],
    ) -> (
        Result<EncryptedStream<TcpStream>, TransportError>,
        Result<EncryptedStream<TcpStream>, TransportError>,
        [u8; 32],
    ) {
        let (v, c) = tcp_pair();
        let coord = Keypair::generate();
        let vol = Keypair::generate();
        let expected = pin(&vol);
        let coord_pin = CoordinatorPin::Key(coord.pubkey_bytes());
        let handle = thread::spawn(move || coordinator_handshake_pinned(c, &coord, expected));
        let v = volunteer_handshake(v, &vol, coord_pin);
        (v, handle.join().unwrap(), vol.pubkey_bytes())
    }

    #[test]
    fn test_pinned_volunteer_is_admitted() {
        let (v, c, vol) = pinned_volunteer_session(|k| k.pubkey_bytes());
        let (mut v, mut c) = (v.unwrap(), c.unwrap());
        assert_eq!(c.peer_identity(), vol);
        v.write_all(b"job").unwrap();
        v.flush().unwrap();
        let mut buf = [0u8; 3];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"job");
    }

    #[test]
    fn test_unpinned_volunteer_is_refused_before_the_coordinator_speaks() {
        let other = Keypair::generate().pubkey_bytes();
        let (v, c, _) = pinned_volunteer_session(|_| other);
        assert!(c.is_err(), "AN0_SEMANTIC volunteer-pin");
        assert!(matches!(c, Err(TransportError::WrongVolunteer { .. })));
        // The coordinator sent no hello: the volunteer sees the stream end.
        assert!(matches!(v, Err(TransportError::Io(_))));
    }

    #[test]
    fn test_forged_coordinator_hello_is_refused() {
        // A hello signed for a different volunteer hello (a replay from
        // another session) does not verify.
        let (v, mut fake) = tcp_pair();
        let coord = Keypair::generate();
        let pin = CoordinatorPin::Key(coord.pubkey_bytes());
        let handle = thread::spawn(move || {
            let mut theirs = [0u8; HELLO_LEN];
            fake.read_exact(&mut theirs).unwrap();
            let eph = EphemeralKeyAgreement::generate();
            let stale = Hello::new(&coord, &eph.public_bytes(), COORDINATOR_CONTEXT);
            fake.write_all(&stale.bytes).unwrap();
        });
        let res = volunteer_handshake(v, &Keypair::generate(), pin);
        handle.join().unwrap();
        assert!(matches!(res, Err(TransportError::BadSignature)));
    }

    #[test]
    fn test_wrong_version_is_refused() {
        let (mut v, c) = tcp_pair();
        let handle = thread::spawn(move || coordinator_handshake(c, &Keypair::generate()));
        v.write_all(&[0u8; HELLO_LEN]).unwrap();
        assert!(matches!(
            handle.join().unwrap(),
            Err(TransportError::BadVersion)
        ));
    }
}
