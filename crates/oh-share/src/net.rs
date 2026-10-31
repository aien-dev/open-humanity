//! Notice delivery over TCP: one connection per notice, one frame each way.
//!
//! The owner only ever connects to addresses it resolved for registered
//! recipients with a grant; nothing here discovers peers or listens on a
//! public address.

use crate::codec::{
    read_frame, write_frame, CodecError, MAX_CONTROL_BYTES, SEAL_HEADER_LEN, SEAL_TAG_LEN,
};
use crate::consent::Key;
use crate::owner::{AckError, DeliveryStatus, OwnerError, OwnerLedger};
use crate::recipient::Recipient;
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// Largest sealed control message on the wire.
pub const MAX_SEALED_CONTROL: u64 = MAX_CONTROL_BYTES + (SEAL_HEADER_LEN + SEAL_TAG_LEN) as u64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryFailure {
    #[error("recipient offline: {0}")]
    Offline(String),
    #[error("recipient did not answer: {0}")]
    NoAnswer(String),
}

/// Sends one sealed notice and waits up to `timeout` for the ack frame.
pub fn deliver_notice(
    addr: SocketAddr,
    sealed: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DeliveryFailure> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| DeliveryFailure::Offline(e.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| DeliveryFailure::NoAnswer(e.to_string()))?;
    write_frame(&mut stream, sealed, MAX_SEALED_CONTROL)
        .map_err(|e| DeliveryFailure::NoAnswer(e.to_string()))?;
    read_frame(&mut stream, MAX_CONTROL_BYTES).map_err(|e| DeliveryFailure::NoAnswer(e.to_string()))
}

/// Answers one connection: reads a sealed notice, lets the recipient
/// enforce it, writes back the signed ack. Undecodable input gets no reply.
pub fn serve_notice_connection(
    mut stream: TcpStream,
    recipient: &Mutex<Recipient>,
    now: u64,
) -> Result<bool, CodecError> {
    let sealed = read_frame(&mut stream, MAX_SEALED_CONTROL)?;
    let ack = recipient
        .lock()
        .expect("recipient lock")
        .handle_notice(&sealed, now);
    match ack {
        Some(ack) => {
            write_frame(&mut stream, &ack, MAX_CONTROL_BYTES)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Result of one delivery round for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundResult {
    pub recipient: Key,
    pub outcome: Result<DeliveryStatus, RoundError>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoundError {
    #[error("no address for recipient")]
    NoAddress,
    #[error("{0}")]
    Delivery(DeliveryFailure),
    #[error("answer was not a valid ack: {0}")]
    BadAck(AckError),
}

/// One delivery round: every pending notice is sent once to the address
/// `resolve` returns. A verified ack updates the status; an offline or
/// silent recipient, or an answer that is not a valid ack, counts as a
/// failed attempt and the notice stays pending until its window closes.
pub fn deliver_pending(
    ledger: &mut OwnerLedger,
    resolve: impl Fn(&Key) -> Option<SocketAddr>,
    timeout: Duration,
    now: u64,
) -> Result<Vec<RoundResult>, OwnerError> {
    let mut results = Vec::new();
    for notice in ledger.outbound_notices(now)? {
        let outcome = match resolve(&notice.recipient) {
            None => Err(RoundError::NoAddress),
            Some(addr) => match deliver_notice(addr, &notice.bytes, timeout) {
                Err(e) => Err(RoundError::Delivery(e)),
                Ok(ack) => ledger.record_ack(&ack, now).map_err(RoundError::BadAck),
            },
        };
        if outcome.is_err() {
            ledger.record_attempt_failed(notice.package_id, notice.recipient, now)?;
        }
        results.push(RoundResult {
            recipient: notice.recipient,
            outcome,
        });
    }
    Ok(results)
}
