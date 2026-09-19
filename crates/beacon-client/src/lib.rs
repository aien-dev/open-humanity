pub mod network;
pub mod preflight;
pub mod storage;

pub use network::*;
pub use preflight::*;
pub use storage::*;

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::schema::{BeaconTopic, DistressNanobeacon, ErrorFingerprint};
    use beacon_core::crypto::Keypair;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    #[test]
    fn test_sqlite_wal_storage_and_sweep() {
        let storage = BeaconStorage::open_in_memory().expect("in-memory db must open");

        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let fp = ErrorFingerprint::from_error_str("test compiler error", Some(101), "aarch64");
        let beacon = DistressNanobeacon::new(
            BeaconTopic::RustCompilation,
            keypair.pubkey_bytes(),
            dh_pubkey,
            fp.clone(),
            "Compilation failure".into(),
            "Cannot borrow as mutable".into(),
        );

        // Record outbound
        storage.record_outbound_beacon(&beacon).expect("outbound record should succeed");

        // Record inbound
        storage.record_inbound_beacon(&beacon).expect("inbound record should succeed");

        // Record solved
        storage.insert_solved_entry(&fp.hash, BeaconTopic::RustCompilation, "use &mut instead")
            .expect("insert solved entry should succeed");

        let solved = storage.get_solved_entry(&fp.hash).expect("query should succeed");
        assert!(solved.is_some());
        let solved = solved.unwrap();
        assert_eq!(solved.solution_patch, "use &mut instead");
        assert!(!solved.promoted_to_cortex);

        // Mark promoted
        storage.mark_promoted_to_cortex(&fp.hash).expect("mark promoted should succeed");
        let solved = storage.get_solved_entry(&fp.hash).unwrap().unwrap();
        assert!(solved.promoted_to_cortex);

        // Sweep (0-second TTL sweeps everything older than now)
        let swept = storage.sweep_expired(0).expect("sweep should succeed");
        assert_eq!(swept, 2);
    }

    #[test]
    fn test_preflight_sandbox_execution() {
        let sandbox = PreflightSandbox::new().expect("sandbox creation should succeed");
        assert!(sandbox.path().exists());

        // Write a test script or simple file
        sandbox.write_file("test.txt", "verification payload").expect("file write should succeed");
        let target_file = sandbox.path().join("test.txt");
        assert!(target_file.exists());

        // Run a basic command inside sandbox
        let receipt = sandbox.run_check("echo", &["sandbox-verified"]).expect("check should pass");
        assert!(receipt.passed);
        assert!(receipt.stdout.contains("sandbox-verified"));

        let path_to_clean = sandbox.path().to_path_buf();
        drop(sandbox);
        assert!(!path_to_clean.exists(), "sandbox directory must be purged on drop");
    }

    #[tokio::test]
    async fn test_network_udp_transport_loopback() {
        let node_a = BeaconTransport::bind("127.0.0.1:0").await.expect("bind A should succeed");
        let node_b = BeaconTransport::bind("127.0.0.1:0").await.expect("bind B should succeed");

        let addr_b = node_b.local_addr().expect("local addr B");

        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let fp = ErrorFingerprint::from_error_str("udp network test error", Some(404), "aarch64");
        let beacon = DistressNanobeacon::new(
            BeaconTopic::ProtocolCoordination,
            keypair.pubkey_bytes(),
            dh_pubkey,
            fp,
            "Network loopback test".into(),
            "Testing 0-RTT broadcast".into(),
        );

        // Broadcast from A to B
        let sent = node_a.broadcast_beacon(&beacon, &[addr_b]).await.expect("send should succeed");
        assert_eq!(sent, 1);

        // Receive on B
        let (received_beacon, src) = node_b.recv_beacon().await.expect("recv should succeed");
        assert_eq!(received_beacon.title, "Network loopback test");
        assert_eq!(received_beacon.topic, BeaconTopic::ProtocolCoordination);
        assert_eq!(src, node_a.local_addr().unwrap());
    }
}
