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
    use rand::rngs::OsRng;
    use std::time::Instant;
    use uuid::Uuid;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    #[test]
    fn test_nanobeacon_packet_size() {
        let keypair = Keypair::generate();
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

        let error_str = "error[E0308]: mismatched types expected struct String, found &str in crates/core/src/lib.rs:42:15";
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

        for item in &items {
            assert!(filter.contains(item));
        }

        let iterations = 100_000;
        let start = Instant::now();
        for i in 0..iterations {
            let item = &items[i % items.len()];
            std::hint::black_box(filter.contains(item));
        }
        let elapsed = start.elapsed();
        let nanos_per_op = elapsed.as_nanos() as f64 / iterations as f64;

        #[cfg(debug_assertions)]
        let max_nanos = 250.0;
        #[cfg(not(debug_assertions))]
        let max_nanos = 10.0;

        assert!(nanos_per_op < max_nanos, "Cuckoo lookup too slow: {:.2} ns (limit: {:.2} ns)", nanos_per_op, max_nanos);
    }

    #[test]
    fn test_firewall_blocks_api_keys() {
        let aws = "Here is my secret AKIAIOSFODNN7EXAMPLE in code";
        assert!(PersonalDataFirewall::verify_clean(aws).is_err());

        let gh = "Authorization: ghp_123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(gh).is_err());

        let oai = "openai_key = sk-123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(oai).is_err());

        let ant = "anthropic_key = sk-ant-123456789012345678901234567890123456";
        assert!(PersonalDataFirewall::verify_clean(ant).is_err());

        let pkey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(PersonalDataFirewall::verify_clean(pkey).is_err());

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
    fn test_firewall_comprehensive_api_key_detection_and_redaction() {
        let oai_proj = "export OPENAI_API_KEY=sk-proj-abcdef1234567890abcdef1234567890";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(oai_proj),
            Err(FirewallViolation::OpenAiKey(_))
        ));

        let ant_key = "ANTHROPIC_KEY=sk-ant-api03-abcdef1234567890123456789012";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(ant_key),
            Err(FirewallViolation::AnthropicKey(_))
        ));

        let gh_pat = format!("token = \"{}{}\"", "ghp_", "123456789012345678901234567890123456");
        let gh_oauth = "token = \"gho_abcdef12345678901234567890123456789012\"";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(&gh_pat),
            Err(FirewallViolation::GitHubToken(_))
        ));
        assert!(matches!(
            PersonalDataFirewall::verify_clean(gh_oauth),
            Err(FirewallViolation::GitHubToken(_))
        ));

        let aws_key = format!("AWS_ACCESS_KEY_ID={}{}", "AKIA", "IOSFODNN7EXAMPLE");
        assert!(matches!(
            PersonalDataFirewall::verify_clean(&aws_key),
            Err(FirewallViolation::AwsKey(_))
        ));

        let google_key = "google_api_key = \"AIzaSyD-1234567890abcdefghijklmnopqrst\"";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(google_key),
            Err(FirewallViolation::GoogleApiKey(_))
        ));

        let stripe_prefix = format!("{}_{}", "sk", "live");
        let stripe_live = format!("STRIPE_KEY={}_51Abcd1234567890abcdef1234567890", stripe_prefix);
        let stripe_rk_prefix = format!("{}_{}", "rk", "live");
        let stripe_rk = format!("RESTRICTED_KEY={}_51Abcd1234567890abcdef1234567890", stripe_rk_prefix);
        assert!(matches!(
            PersonalDataFirewall::verify_clean(&stripe_live),
            Err(FirewallViolation::StripeKey(_))
        ));
        assert!(matches!(
            PersonalDataFirewall::verify_clean(&stripe_rk),
            Err(FirewallViolation::StripeKey(_))
        ));

        let hf_token = "HF_AUTH=hf_Abcdefghijklmnopqrstuvwxyz12345678";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(hf_token),
            Err(FirewallViolation::HuggingFaceToken(_))
        ));

        let test_gh_pat = format!("{}{}", "ghp_", "123456789012345678901234567890123456");
        let test_aws_key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let test_stripe_token = format!("{}_{}", "sk_live", "51Abcd1234567890abcdef1234567890");
        let combined = format!(
            "Keys: sk-proj-abcdef1234567890abcdef1234567890, sk-ant-api03-abcdef1234567890123456789012, {}, {}, AIzaSyD-1234567890abcdefghijklmnopqrst, {}, hf_Abcdefghijklmnopqrstuvwxyz12345678",
            test_gh_pat, test_aws_key, test_stripe_token
        );
        let redacted = PersonalDataFirewall::redact_secrets(&combined);
        assert!(!redacted.contains("sk-proj-"));
        assert!(!redacted.contains("sk-ant-"));
        assert!(!redacted.contains("ghp_"));
        assert!(!redacted.contains("AKIA"));
        assert!(!redacted.contains("AIza"));
        assert!(!redacted.contains("sk_live_"));
        assert!(!redacted.contains("hf_"));
        assert!(redacted.contains("[REDACTED_OPENAI_KEY]"));
        assert!(redacted.contains("[REDACTED_ANTHROPIC_KEY]"));
        assert!(redacted.contains("[REDACTED_GITHUB_TOKEN]"));
        assert!(redacted.contains("[REDACTED_AWS_KEY]"));
        assert!(redacted.contains("[REDACTED_GOOGLE_KEY]"));
        assert!(redacted.contains("[REDACTED_STRIPE_KEY]"));
        assert!(redacted.contains("[REDACTED_HF_TOKEN]"));
    }

    #[test]
    fn test_firewall_filesystem_path_sanitization_all_platforms() {
        let linux_path = "/home/drakestapleton/workspace/open-humanity/target/debug/lib.rs";
        let cleaned_linux = PersonalDataFirewall::sanitize_paths(linux_path);
        assert_eq!(cleaned_linux, "~/workspace/open-humanity/target/debug/lib.rs");

        let macos_path = "/Users/drakestapleton/Library/Application Support/OpenHumanity/config.json";
        let cleaned_macos = PersonalDataFirewall::sanitize_paths(macos_path);
        assert_eq!(cleaned_macos, "~/Library/Application Support/OpenHumanity/config.json");

        let win_path = "C:\\Users\\drakestapleton\\AppData\\Local\\OpenHumanity\\vault.key";
        let cleaned_win = PersonalDataFirewall::sanitize_paths(win_path);
        assert_eq!(cleaned_win, "~\\AppData\\Local\\OpenHumanity\\vault.key");

        let win_slash_path = "C:/Users/drakestapleton/AppData/Local/OpenHumanity/vault.key";
        let cleaned_win_slash = PersonalDataFirewall::sanitize_paths(win_slash_path);
        assert_eq!(cleaned_win_slash, "~/AppData/Local/OpenHumanity/vault.key");

        let traversal = "../../../../etc/shadow";
        let cleaned_traversal = PersonalDataFirewall::sanitize_paths(traversal);
        assert_eq!(cleaned_traversal, "./etc/shadow");

        let traversal_attempt = "cat ../../etc/passwd";
        assert!(matches!(
            PersonalDataFirewall::verify_clean(traversal_attempt),
            Err(FirewallViolation::PathTraversal(_))
        ));
    }

    #[test]
    fn test_firewall_unicode_normalization_and_obfuscation() {
        let zwsp_ant = "sk-\u{200B}ant-api03-abcdef1234567890123456789012";
        assert!(PersonalDataFirewall::verify_clean(zwsp_ant).is_err());

        let zwsp_aws = "A\u{200C}K\u{200D}IAIOSFODNN7EXAMPLE";
        assert!(PersonalDataFirewall::verify_clean(zwsp_aws).is_err());

        let urlenc_ant = "%73%6b%2d%61%6e%74%2dapi03%2dabcdef1234567890123456789012";
        assert!(PersonalDataFirewall::verify_clean(urlenc_ant).is_err());

        let urlenc_traversal = "%2e%2e%2f%2e%2e%2fetc/passwd";
        assert!(PersonalDataFirewall::verify_clean(urlenc_traversal).is_err());

        let leet_secret = "4pi_k3y = 'abcdef01234567890123456789'";
        assert!(PersonalDataFirewall::verify_clean(leet_secret).is_err());
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

    #[test]
    fn test_crypto_chacha20_poly1305_randomized_roundtrips() {
        let payload_sizes = [0usize, 1, 16, 64, 256, 1024, 4096];
        for size in payload_sizes {
            let recipient_secret = StaticSecret::random_from_rng(OsRng);
            let recipient_pubkey = *X25519PublicKey::from(&recipient_secret).as_bytes();

            let mut message = vec![0u8; size];
            rand::RngCore::fill_bytes(&mut OsRng, &mut message);

            let encrypted = encrypt_to_peer(&recipient_pubkey, &message)
                .expect("encryption of random payload should succeed");

            let decrypted = decrypt_from_peer(
                &recipient_secret,
                &encrypted.ephemeral_pubkey,
                &encrypted.nonce,
                &encrypted.ciphertext,
            ).expect("decryption of random payload should succeed");

            assert_eq!(decrypted, message, "Payload roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_crypto_tampering_detection_single_bit_flip() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_pubkey = *X25519PublicKey::from(&recipient_secret).as_bytes();
        let message = b"Confidential diagnosis payload for peer review";

        let encrypted = encrypt_to_peer(&recipient_pubkey, message)
            .expect("encryption should succeed");

        for byte_idx in 0..encrypted.ciphertext.len() {
            for bit in 0..8 {
                let mut tampered_ciphertext = encrypted.ciphertext.clone();
                tampered_ciphertext[byte_idx] ^= 1 << bit;

                let result = decrypt_from_peer(
                    &recipient_secret,
                    &encrypted.ephemeral_pubkey,
                    &encrypted.nonce,
                    &tampered_ciphertext,
                );
                assert_eq!(
                    result,
                    Err(BeaconError::DecryptionFailed),
                    "Single bit flip at byte {} bit {} went undetected",
                    byte_idx,
                    bit
                );
            }
        }
    }

    #[test]
    fn test_crypto_tampering_detection_altered_auth_tags() {
        let recipient_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_pubkey = *X25519PublicKey::from(&recipient_secret).as_bytes();
        let message = b"Authenticated payload integrity test";

        let encrypted = encrypt_to_peer(&recipient_pubkey, message)
            .expect("encryption should succeed");

        let tag_start = encrypted.ciphertext.len().saturating_sub(16);
        for tag_idx in tag_start..encrypted.ciphertext.len() {
            let mut corrupted = encrypted.ciphertext.clone();
            corrupted[tag_idx] ^= 0xFF;

            let result = decrypt_from_peer(
                &recipient_secret,
                &encrypted.ephemeral_pubkey,
                &encrypted.nonce,
                &corrupted,
            );
            assert_eq!(
                result,
                Err(BeaconError::DecryptionFailed),
                "Corrupted authentication tag at byte {} went undetected",
                tag_idx
            );
        }
    }

    #[test]
    fn test_crypto_tampering_detection_mismatched_keys() {
        let recipient_a_secret = StaticSecret::random_from_rng(OsRng);
        let recipient_a_pubkey = *X25519PublicKey::from(&recipient_a_secret).as_bytes();

        let recipient_b_secret = StaticSecret::random_from_rng(OsRng);

        let message = b"Targeted payload for recipient A";
        let encrypted = encrypt_to_peer(&recipient_a_pubkey, message)
            .expect("encryption should succeed");

        let result = decrypt_from_peer(
            &recipient_b_secret,
            &encrypted.ephemeral_pubkey,
            &encrypted.nonce,
            &encrypted.ciphertext,
        );
        assert_eq!(
            result,
            Err(BeaconError::DecryptionFailed),
            "Decryption by mismatched key unexpectedly succeeded"
        );
    }

    #[test]
    fn test_crypto_replay_attack_resistance() {
        let mut protector = ReplayProtector::new(100);
        let packet_id = Uuid::now_v7();

        assert!(protector.check_and_record(&packet_id).is_ok());

        let replay_result = protector.check_and_record(&packet_id);
        assert_eq!(
            replay_result,
            Err(BeaconError::ReplayDetected(packet_id)),
            "Replay of identical packet ID must be rejected"
        );

        let distinct_id = Uuid::now_v7();
        assert!(protector.check_and_record(&distinct_id).is_ok());
    }

    #[test]
    fn test_crypto_timestamp_drift_verification() {
        let base_time: u64 = 1_700_000_000;
        let max_drift: u64 = 300;

        assert!(verify_timestamp_drift(base_time, base_time, max_drift).is_ok());
        assert!(verify_timestamp_drift(base_time + 120, base_time, max_drift).is_ok());
        assert!(verify_timestamp_drift(base_time - 120, base_time, max_drift).is_ok());
        assert!(verify_timestamp_drift(base_time + 300, base_time, max_drift).is_ok());
        assert!(verify_timestamp_drift(base_time - 300, base_time, max_drift).is_ok());

        assert!(matches!(
            verify_timestamp_drift(base_time + 301, base_time, max_drift),
            Err(BeaconError::TimestampDrift { drift_secs: 301, max_allowed: 300 })
        ));

        assert!(matches!(
            verify_timestamp_drift(base_time - 500, base_time, max_drift),
            Err(BeaconError::TimestampDrift { drift_secs: 500, max_allowed: 300 })
        ));
    }
}
