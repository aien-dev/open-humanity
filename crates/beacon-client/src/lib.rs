pub mod network;
pub mod preflight;
pub mod storage;

pub use network::*;
pub use preflight::*;
pub use storage::*;

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_core::crypto::Keypair;
    use beacon_core::schema::{BeaconTopic, DistressNanobeacon, ErrorFingerprint};
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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

        storage.record_outbound_beacon(&beacon).expect("outbound record should succeed");
        storage.record_inbound_beacon(&beacon).expect("inbound record should succeed");

        storage.insert_solved_entry(&fp.hash, BeaconTopic::RustCompilation, "use &mut instead")
            .expect("insert solved entry should succeed");

        let solved = storage.get_solved_entry(&fp.hash).expect("query should succeed");
        assert!(solved.is_some());
        let solved = solved.unwrap();
        assert_eq!(solved.solution_patch, "use &mut instead");
        assert!(!solved.promoted_to_cortex);

        storage.mark_promoted_to_cortex(&fp.hash).expect("mark promoted should succeed");
        let solved = storage.get_solved_entry(&fp.hash).unwrap().unwrap();
        assert!(solved.promoted_to_cortex);

        let swept = storage.sweep_expired(0).expect("sweep should succeed");
        assert_eq!(swept, 2);
    }

    #[tokio::test]
    async fn test_storage_concurrent_signal_insertions_tokio_contention() {
        let temp_dir = tempfile::tempdir().expect("tempdir creation should succeed");
        let db_path = temp_dir.path().join("signal_contention.sqlite");

        {
            let init_storage = BeaconStorage::open(&db_path).expect("init db must succeed");
            assert_eq!(init_storage.count_outbound().unwrap(), 0);
        }

        let num_tasks = 16;
        let inserts_per_task = 5;
        let path_arc = Arc::new(db_path.clone());
        let mut handles = Vec::new();

        for task_idx in 0..num_tasks {
            let path_clone = Arc::clone(&path_arc);
            let handle = tokio::spawn(async move {
                let storage = BeaconStorage::open(&*path_clone).expect("task db open must succeed");
                for i in 0..inserts_per_task {
                    let keypair = Keypair::generate();
                    let dh_secret = StaticSecret::random_from_rng(OsRng);
                    let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();
                    let err_msg = format!("task-{}-iter-{}", task_idx, i);
                    let fp = ErrorFingerprint::from_error_str(&err_msg, Some(task_idx as u32), "aarch64");
                    let signal = DistressNanobeacon::new(
                        BeaconTopic::RustCompilation,
                        keypair.pubkey_bytes(),
                        dh_pubkey,
                        fp,
                        format!("Task {} Signal {}", task_idx, i),
                        "Concurrent contention signal".into(),
                    );
                    storage.record_outbound_beacon(&signal).expect("concurrent record must succeed");
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("task must join cleanly without error");
        }

        let verify_storage = BeaconStorage::open(&db_path).expect("verify db open must succeed");
        let total_count = verify_storage.count_outbound().expect("count query must succeed");
        assert_eq!(
            total_count,
            num_tasks * inserts_per_task,
            "Exact count of concurrently inserted signals must match total attempts"
        );
    }

    #[test]
    fn test_storage_automated_sweep_and_expiry() {
        let storage = BeaconStorage::open_in_memory().expect("in-memory db must open");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let make_signal = |title: &str| {
            let fp = ErrorFingerprint::from_error_str(title, None, "aarch64");
            DistressNanobeacon::new(
                BeaconTopic::RustCompilation,
                keypair.pubkey_bytes(),
                dh_pubkey,
                fp,
                title.into(),
                "summary".into(),
            )
        };

        let fresh1 = make_signal("Fresh signal 1");
        storage.record_outbound_beacon(&fresh1).unwrap();

        let fresh2 = make_signal("Fresh signal 2");
        storage.record_outbound_beacon(&fresh2).unwrap();

        let stale_created = now.saturating_sub(700_000);
        {
            let mut storage_test = BeaconStorage::open_in_memory().unwrap();
            let tx = storage_test.transaction().unwrap();

            let sig1 = make_signal("Fresh A");
            let sig2 = make_signal("Fresh B");
            BeaconStorage::record_outbound_beacon_tx(&tx, &sig1).unwrap();
            BeaconStorage::record_outbound_beacon_tx(&tx, &sig2).unwrap();

            for i in 0..3 {
                let stale = make_signal(&format!("Stale {}", i));
                tx.execute(
                    "INSERT INTO beacons_out (
                        id, timestamp, topic, sender_pubkey, fingerprint_hash,
                        compiler_code, arch, title, compact_summary, status, created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        stale.beacon_id.to_string(),
                        stale.timestamp,
                        stale.topic as u8,
                        &stale.sender_pubkey[..],
                        &stale.fingerprint.hash[..],
                        stale.fingerprint.compiler_code,
                        stale.fingerprint.hardware_arch,
                        stale.title,
                        stale.compact_summary,
                        "pending",
                        stale_created,
                    ],
                ).unwrap();
            }
            tx.commit().unwrap();

            assert_eq!(storage_test.count_outbound().unwrap(), 5);
            let swept = storage_test.sweep_expired(604800).unwrap();
            assert_eq!(swept, 3, "Exactly 3 stale signals must be swept");
            assert_eq!(storage_test.count_outbound().unwrap(), 2, "2 fresh signals must remain");
        }
    }

    #[test]
    fn test_storage_transaction_rollback_simulated_io_error() {
        let mut storage = BeaconStorage::open_in_memory().expect("in-memory db must open");

        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let fp1 = ErrorFingerprint::from_error_str("Baseline signal", None, "aarch64");
        let baseline = DistressNanobeacon::new(
            BeaconTopic::RustCompilation,
            keypair.pubkey_bytes(),
            dh_pubkey,
            fp1,
            "Baseline signal".into(),
            "Persisted before transaction".into(),
        );

        storage.record_outbound_beacon(&baseline).expect("baseline insert must succeed");
        assert_eq!(storage.count_outbound().unwrap(), 1);

        let simulated_error: Result<(), StorageError> = (|| {
            let tx = storage.transaction()?;

            let fp2 = ErrorFingerprint::from_error_str("Uncommitted A", None, "aarch64");
            let sig_a = DistressNanobeacon::new(
                BeaconTopic::RustCompilation,
                keypair.pubkey_bytes(),
                dh_pubkey,
                fp2,
                "Uncommitted A".into(),
                "Should be rolled back".into(),
            );
            BeaconStorage::record_outbound_beacon_tx(&tx, &sig_a)?;

            let fp3 = ErrorFingerprint::from_error_str("Uncommitted B", None, "aarch64");
            let sig_b = DistressNanobeacon::new(
                BeaconTopic::RustCompilation,
                keypair.pubkey_bytes(),
                dh_pubkey,
                fp3,
                "Uncommitted B".into(),
                "Should be rolled back".into(),
            );
            BeaconStorage::record_outbound_beacon_tx(&tx, &sig_b)?;

            Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Simulated disk IO error during transaction",
            )))
        })();

        assert!(simulated_error.is_err(), "Transaction closure must return IO error");
        assert_eq!(
            storage.count_outbound().unwrap(),
            1,
            "Database count must remain at 1 because aborted transaction rolled back all mutations"
        );

        {
            let tx = storage.transaction().unwrap();
            let fp_committed = ErrorFingerprint::from_error_str("Committed B", None, "aarch64");
            let sig_c = DistressNanobeacon::new(
                BeaconTopic::RustCompilation,
                keypair.pubkey_bytes(),
                dh_pubkey,
                fp_committed,
                "Committed B".into(),
                "Should be committed".into(),
            );
            BeaconStorage::record_outbound_beacon_tx(&tx, &sig_c).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(
            storage.count_outbound().unwrap(),
            2,
            "Database count must increase to 2 after successful commit"
        );
    }

    #[test]
    fn test_preflight_sandbox_execution() {
        let sandbox = PreflightSandbox::new().expect("sandbox creation should succeed");
        assert!(sandbox.path().exists());

        sandbox.write_file("test.txt", "verification payload").expect("file write should succeed");
        let target_file = sandbox.path().join("test.txt");
        assert!(target_file.exists());

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

        let sent = node_a.broadcast_beacon(&beacon, &[addr_b]).await.expect("send should succeed");
        assert_eq!(sent, 1);

        let (received_beacon, src) = node_b.recv_beacon().await.expect("recv should succeed");
        assert_eq!(received_beacon.title, "Network loopback test");
        assert_eq!(received_beacon.topic, BeaconTopic::ProtocolCoordination);
        assert_eq!(src, node_a.local_addr().unwrap());
    }
}
