//! High-performance UDP datagram transport for Open Humanity nanobeacons.
//!
//! Enforces zero-copy MTU packet limits (<= 1,200 bytes) for 0-RTT broadcast
//! across peer rings.

use beacon_core::schema::{BeaconError, DistressNanobeacon, ResolutionCapsule, MAX_DATAGRAM_SIZE};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Beacon protocol error: {0}")]
    Protocol(#[from] BeaconError),
    #[error("Packet exceeds maximum MTU size: {0} > {1}")]
    MtuExceeded(usize, usize),
}

#[derive(Clone)]
pub struct BeaconTransport {
    socket: Arc<UdpSocket>,
}

impl BeaconTransport {
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<Self, NetworkError> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn broadcast_beacon(
        &self,
        beacon: &DistressNanobeacon,
        targets: &[SocketAddr],
    ) -> Result<usize, NetworkError> {
        let bytes = beacon.to_bytes()?;
        if bytes.len() > MAX_DATAGRAM_SIZE {
            return Err(NetworkError::MtuExceeded(bytes.len(), MAX_DATAGRAM_SIZE));
        }

        let mut sent = 0;
        for target in targets {
            if self.socket.send_to(&bytes, target).await.is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub async fn recv_beacon(&self) -> Result<(DistressNanobeacon, SocketAddr), NetworkError> {
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        let (len, src) = self.socket.recv_from(&mut buf).await?;
        let beacon = DistressNanobeacon::from_bytes(&buf[..len])?;
        Ok((beacon, src))
    }

    pub async fn send_capsule(
        &self,
        capsule: &ResolutionCapsule,
        target: SocketAddr,
    ) -> Result<usize, NetworkError> {
        let bytes = capsule.to_bytes()?;
        let len = self.socket.send_to(&bytes, target).await?;
        Ok(len)
    }

    pub async fn recv_capsule(&self) -> Result<(ResolutionCapsule, SocketAddr), NetworkError> {
        let mut buf = [0u8; 65535];
        let (len, src) = self.socket.recv_from(&mut buf).await?;
        let capsule = ResolutionCapsule::from_bytes(&buf[..len])?;
        Ok((capsule, src))
    }
}
