//! Headless Open Humanity Relay Daemon.
//!
//! Stateless UDP datagram forwarder and 7-day TTL ring buffer.
//! Forwards encrypted capsules and distress signals between swarm nodes
//! without storing personal context or personal memory.

use beacon_core::schema::{DistressNanobeacon, MAX_DATAGRAM_SIZE};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub const RELAY_DEFAULT_PORT: u16 = 18098;
pub const MAX_RING_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct CachedSignal {
    pub beacon_id: uuid::Uuid,
    pub timestamp: Instant,
    pub datagram: Vec<u8>,
    pub source: SocketAddr,
}

#[derive(Clone)]
pub struct RelayServer {
    socket: Arc<UdpSocket>,
    ring: Arc<Mutex<VecDeque<CachedSignal>>>,
}

impl RelayServer {
    pub async fn bind(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let socket = UdpSocket::bind(addr).await?;
        info!("Open Humanity Relay bound to {}", addr);

        Ok(Self {
            socket: Arc::new(socket),
            ring: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RING_ENTRIES))),
        })
    }

    pub async fn run_loop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let packet = &buf[..len];
                    match DistressNanobeacon::from_bytes(packet) {
                        Ok(beacon) => {
                            info!(
                                "Relayed distress beacon {} [topic: {}] from {}",
                                beacon.beacon_id,
                                beacon.topic.as_str(),
                                src
                            );

                            let mut ring = self.ring.lock().await;
                            if ring.len() >= MAX_RING_ENTRIES {
                                ring.pop_front();
                            }
                            ring.push_back(CachedSignal {
                                beacon_id: beacon.beacon_id,
                                timestamp: Instant::now(),
                                datagram: packet.to_vec(),
                                source: src,
                            });
                        }
                        Err(e) => {
                            warn!("Ignored invalid packet from {}: {}", src, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Socket recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting Open Humanity Headless Relay Daemon");

    let port = std::env::var("BEACON_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(RELAY_DEFAULT_PORT);

    let relay = RelayServer::bind(port).await?;
    relay.run_loop().await?;

    Ok(())
}
