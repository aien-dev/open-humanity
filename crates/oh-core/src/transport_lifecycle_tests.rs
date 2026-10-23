use super::*;
use std::io::Cursor;

#[derive(Default)]
struct Scripted {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_fault: Option<(usize, io::ErrorKind)>,
    write_fault: Option<(usize, io::ErrorKind)>,
    flush_error: bool,
    reads: usize,
    writes: usize,
}
impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if let Some((at, kind)) = self.read_fault {
            if self.input.position() as usize == at {
                self.read_fault = None;
                return Err(kind.into());
            }
        }
        let n = buf.len().min(1);
        self.input.read(&mut buf[..n])
    }
}
impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if let Some((at, kind)) = self.write_fault {
            if self.output.len() == at {
                self.write_fault = None;
                return Err(kind.into());
            }
        }
        let n = buf.len().min(1);
        self.output.extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_error {
            self.flush_error = false;
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(())
        }
    }
}
fn stream(io: Scripted) -> EncryptedStream<Scripted> {
    EncryptedStream::new(io, &[1; 32], &[1; 32], [2; 32])
}
fn record(counter: u64) -> Vec<u8> {
    let mut s = stream(Scripted::default());
    s.send_counter = counter;
    s.write_all(b"synthetic").unwrap();
    s.flush().unwrap();
    s.inner.output
}
fn assert_terminal(s: &mut EncryptedStream<Scripted>) {
    let calls = (s.inner.reads, s.inner.writes, s.inner.output.len());
    assert!(s.read(&mut [0; 1]).is_err(), "terminal read must refuse");
    assert!(s.write(b"later").is_err(), "terminal write must refuse");
    assert!(s.flush().is_err(), "terminal flush must refuse");
    assert_eq!(
        calls,
        (s.inner.reads, s.inner.writes, s.inner.output.len()),
        "terminal session must not touch raw I/O"
    );
    assert_eq!(s.read(&mut []).unwrap(), 0);
    assert_eq!(s.write(&[]).unwrap(), 0);
}
#[test]
fn terminal_partial_reads_and_eof() {
    let wire = record(0);
    for end in [1, 3, 4, 5, wire.len() - 1] {
        let mut s = stream(Scripted {
            input: Cursor::new(wire[..end].to_vec()),
            ..Default::default()
        });
        assert_eq!(
            s.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_terminal(&mut s);
    }
    let mut clean = stream(Scripted::default());
    assert_eq!(clean.read(&mut [0; 1]).unwrap(), 0);
}
#[test]
fn terminal_io_errors_at_record_boundaries() {
    for at in [0, 1, 3, 4, 19] {
        let mut s = stream(Scripted {
            input: Cursor::new(record(0)),
            read_fault: Some((at, io::ErrorKind::Other)),
            ..Default::default()
        });
        assert_eq!(
            s.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_terminal(&mut s);
        let mut s = stream(Scripted {
            write_fault: Some((at, io::ErrorKind::Other)),
            ..Default::default()
        });
        s.write_all(b"synthetic").unwrap();
        assert!(s.flush().is_err());
        assert_eq!(s.send_counter, 1, "failed write cannot roll nonce back");
        assert_terminal(&mut s);
    }
    let mut s = stream(Scripted {
        flush_error: true,
        ..Default::default()
    });
    s.write_all(b"synthetic").unwrap();
    assert!(s.flush().is_err());
    assert_terminal(&mut s);
}
#[test]
fn interrupted_short_io_resumes_exactly_once() {
    let expected = record(0);
    for at in [0, 1, 3, 4, 19, expected.len() - 1] {
        let mut s = stream(Scripted {
            write_fault: Some((at, io::ErrorKind::Interrupted)),
            ..Default::default()
        });
        s.write_all(b"synthetic").unwrap();
        s.flush().unwrap();
        s.flush().unwrap();
        assert_eq!(s.inner.output, expected);
        assert_eq!(s.send_counter, 1);
        let mut s = stream(Scripted {
            input: Cursor::new(expected.clone()),
            read_fault: Some((at, io::ErrorKind::Interrupted)),
            ..Default::default()
        });
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"synthetic");
        assert_eq!(s.recv_counter, 1);
    }
}
#[test]
fn counters_stop_before_wrap_without_io() {
    let mut send = stream(Scripted::default());
    send.send_counter = u64::MAX - 1;
    send.write_all(b"synthetic").unwrap();
    send.flush().unwrap();
    assert_eq!(send.send_counter, u64::MAX);
    send.write_all(b"last").unwrap();
    assert!(
        send.flush().is_err(),
        "send exhaustion must refuse before nonce wrap"
    );
    assert_eq!(send.send_counter, u64::MAX);
    assert_terminal(&mut send);
    let mut recv = stream(Scripted {
        input: Cursor::new(record(u64::MAX - 1)),
        ..Default::default()
    });
    recv.recv_counter = u64::MAX - 1;
    let mut data = [0; 9];
    recv.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"synthetic");
    assert_eq!(recv.recv_counter, u64::MAX);
    let calls = recv.inner.reads;
    assert!(
        recv.read(&mut [0; 1]).is_err(),
        "exhaustion must be refused before any read or increment"
    );
    assert_eq!(calls, recv.inner.reads);
    assert_terminal(&mut recv);
}
#[test]
fn transcript_binding_with_persistent_identity_and_fixed_shared_secret() {
    let id = Keypair::from_seed(&[3; 32]);
    let v1 = Hello::new(&id, &[4; 32], VOLUNTEER_CONTEXT);
    let v2 = Hello::new(&id, &[5; 32], VOLUNTEER_CONTEXT);
    let c1 = Hello::new(&id, &[6; 32], &coordinator_prefix(&v1));
    let c2 = Hello::new(&id, &[7; 32], &coordinator_prefix(&v2));
    let (k1, other) = session_keys(&[8; 32], &v1, &c1);
    let (k2, _) = session_keys(&[8; 32], &v2, &c2);
    assert_ne!(
        k1, k2,
        "fresh transcript must bind keys even with identical shared secret"
    );
    assert_ne!(k1, other);
    let mut old = EncryptedStream::new(Scripted::default(), &k1, &other, id.pubkey_bytes());
    old.write_all(b"old session").unwrap();
    old.flush().unwrap();
    let mut new = EncryptedStream::new(
        Scripted {
            input: Cursor::new(old.inner.output),
            ..Default::default()
        },
        &other,
        &k2,
        id.pubkey_bytes(),
    );
    assert_eq!(
        new.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_terminal(&mut new);
}
#[test]
fn protocol_failure_poison_is_whole_session() {
    let mut s = stream(Scripted {
        input: Cursor::new(vec![0; 4]),
        ..Default::default()
    });
    assert_eq!(
        s.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_terminal(&mut s);
}
