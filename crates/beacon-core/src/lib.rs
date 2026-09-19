pub mod crypto;
pub mod cuckoo;
pub mod firewall;
pub mod schema;

pub use crypto::*;
pub use cuckoo::*;
pub use firewall::*;
pub use schema::*;

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
    use rand::rngs::OsRng;
    use std::time::Instant;

    #[test]
    fn test_nanobeacon_packet_size() {
        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let error_str = "error[E0308]: mismatched types expected struct `String`, found `&str` in crates/core/src/lib.rs:42:15";
        let fp = ErrorFingerprint::from_error_str(error_str, Some(308), "aarch64");

        let beacon = DistressNanobeacon::new(
            BeaconTopic::RustCompilation,
            keypair.pubkey_bytes(),
            dh_pubkey,
            fp,
            "Rust E0308 string mismatch".to_string(),
            "Compiler expects owned String instead of string slice in handler".to_string(),
        );

        let bytes = beacon.to_bytes().expect("serialization should succeed");
        assert!(
            bytes.len() <= MAX_DATAGRAM_SIZE,
            "Datagram size {} exceeds limit of {}",
            bytes.len(),
            MAX_DATAGRAM_SIZE
        );

        let decoded = DistressNanobeacon::from_bytes(&bytes).expect("deserialization should succeed");
        assert_eq!(decoded.magic, MAGIC_BYTES);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.topic, BeaconTopic::RustCompilation);
        assert_eq!(decoded.title, "Rust E0308 string mismatch");
    }

    #[test]
    fn test_cuckoo_lookup_speed() {
        let mut filter = CuckooFilter::new();
        let mut items = Vec::new();

        for i in 0..1000 {
            let item = *blake3::hash(format!("error-signature-{}", i).as_bytes()).as_bytes();
            filter.insert(&item);
            items.push(item);
        }

        assert_eq!(filter.len(), 1000);

        // Verify lookup correctness
        for item in &items {
            assert!(filter.contains(item));
        }

        // Benchmark lookup throughput
        let iterations = 100_000;
        let start = Instant::now();
        for i in 0..iterations {
            let item = &items[i % items.len()];
            std::hint::black_box(filter.contains(item));
        }
        let elapsed = start.elapsed();
        let nanos_per_op = elapsed.as_nanos() as f64 / iterations as f64;
        println!("Cuckoo lookup latency: {:.2} ns per lookup", nanos_per_op);

        #[cfg(debug_assertions)]
        let max_nanos = 250.0;
        #[cfg(not(debug_assertions))]
        let max_nanos = 10.0;

        assert!(nanos_per_op < max_nanos, "Cuckoo lookup too slow: {:.2} ns (limit: {:.2} ns)", nanos_per_op, max_nanos);
    }

    #[test]
    fn test_firewall_blocks_api_keys() {
        // AWS key
        let aws = "Here is my secret AKIAIOSFODNN7EXAMPLE in code";
        assert!(PersonalDataFirewall::verify_clean(aws).is_err());

        // GitHub token
        let gh = "Authorization: ghp_123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(gh).is_err());

        // OpenAI key
        let oai = "openai_key = sk-123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(oai).is_err());

        // Anthropic key
        let ant = "anthropic_key = sk-ant-123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(ant).is_err());

        // Private key block
        let pkey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(PersonalDataFirewall::verify_clean(pkey).is_err());

        // Clean code
        let clean = "fn calculate_hash(data: &[u8]) -> [u8; 32] { blake3::hash(data).into() }";
        assert!(PersonalDataFirewall::verify_clean(clean).is_ok());
    }

    #[test]
    fn test_firewall_sanitizes_paths() {
        let dirty = "Failure occurred at /home/drakestapleton/workspace/open-humanity/crates/lib.rs:10";
        let cleaned = PersonalDataFirewall::sanitize_paths(dirty);
        assert_eq!(cleaned, "Failure occurred at ~/workspace/open-humanity/crates/lib.rs:10");
        assert!(!cleaned.contains("/home/drakestapleton/"));
    }

    #[test]
    fn test_crypto_encryption_cycle() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_pubkey = *X25519PublicKey::from(&recipient_secret).as_bytes();

        let message = b"fn solve() { println!(\"Fix applied\"); }";
        let encrypted = encrypt_to_peer(&recipient_pubkey, message)
            .expect("encryption should succeed");

        let decrypted = decrypt_from_peer(
            &recipient_secret,
            &encrypted.ephemeral_pubkey,
            &encrypted.nonce,
            &encrypted.ciphertext,
        ).expect("decryption should succeed");

        assert_eq!(decrypted, message);
    }
}
