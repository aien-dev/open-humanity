use super::*;
include!("crypto_reuse_primitive_tests.rs");

#[test]
fn replay_capacity_retains_history() {
    for capacity in 0..=2 {
        let mut p = ReplayProtector::new(capacity);
        for n in 0..capacity {
            let id = Uuid::from_u128(n as u128 + 1);
            assert_eq!(p.check_and_record(&id), Ok(()));
            assert_eq!(
                p.check_and_record(&id),
                Err(BeaconError::ReplayDetected(id))
            );
        }
        for n in 3..8 {
            assert_eq!(
                p.check_and_record(&Uuid::from_u128(n)),
                Err(BeaconError::ReplayCapacityExceeded(capacity)),
                "capacity must refuse, never erase history"
            );
            assert_eq!(
                p.len(),
                capacity,
                "overflow must retain exactly the original IDs"
            );
            for old in 0..capacity {
                let id = Uuid::from_u128(old as u128 + 1);
                assert_eq!(
                    p.check_and_record(&id),
                    Err(BeaconError::ReplayDetected(id)),
                    "replay remains refused after overflow"
                );
            }
        }
    }
}

// RFC 7748 non-contributory points: u=0, u=1 and u=p-1 (order 2).
fn low_order_points() -> [[u8; 32]; 3] {
    let zero = [0; 32];
    let mut one = zero;
    one[0] = 1;
    let mut pm1 = [255; 32];
    pm1[0] = 236;
    pm1[31] = 127;
    [zero, one, pm1]
}

#[test]
fn peer_encrypt_refuses_noncontributory() {
    for public in low_order_points() {
        assert!(
            matches!(
                encrypt_to_peer(&public, b"synthetic"),
                Err(BeaconError::KeyAgreementFailed)
            ),
            "encrypt must reject low-order agreement before cipher use"
        );
    }
}

#[test]
fn peer_decrypt_refuses_predictable_zero_key_forgery() {
    let secret = StaticSecret::from([7; 32]);
    let nonce = [9; 12];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&[0; 32]));
    let forged = cipher
        .encrypt(Nonce::from_slice(&nonce), b"synthetic forgery".as_slice())
        .unwrap();
    for public in low_order_points() {
        assert!(
            matches!(
                decrypt_from_peer(&secret, &public, &nonce, &forged),
                Err(BeaconError::KeyAgreementFailed)
            ),
            "decrypt must reject predictable zero-key forgery at agreement"
        );
    }
}
