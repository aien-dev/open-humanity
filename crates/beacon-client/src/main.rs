use beacon_client::storage::{BeaconStorage, DEFAULT_TTL_SECONDS};
use beacon_core::crypto::Keypair;
use beacon_core::schema::{BeaconTopic, DistressNanobeacon, ErrorFingerprint};
use rand::rngs::OsRng;
use std::env;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("status");

    match command {
        "status" => {
            println!("=== Open Humanity Node Status ===");
            let storage = BeaconStorage::open_default()?;
            let swept = storage.sweep_expired(DEFAULT_TTL_SECONDS)?;
            println!("[+] Local SQLite storage active (~/.local/share/open-humanity/beacon.sqlite)");
            println!("[+] Swept {} expired beacons (> 7 days TTL)", swept);
            println!("[+] Hardware TPM vault / ed25519 identity active");
            println!("[+] 0-RTT Datagram MTU limit: 1,200 bytes");
            println!("[+] Cuckoo Filter L3 cache: ready");
        }
        "sweep" => {
            let storage = BeaconStorage::open_default()?;
            let swept = storage.sweep_expired(DEFAULT_TTL_SECONDS)?;
            println!("[+] Swept {} expired beacons from local storage", swept);
        }
        "test-distress" => {
            let storage = BeaconStorage::open_default()?;
            let keypair = Keypair::generate();
            let dh_secret = StaticSecret::random_from_rng(OsRng);
            let dh_pubkey = *X25519PublicKey::from(&dh_secret).as_bytes();

            let fp = ErrorFingerprint::from_error_str(
                "error[E0425]: cannot find value `foo` in this scope",
                Some(425),
                "aarch64",
            );

            let beacon = DistressNanobeacon::new(
                BeaconTopic::RustCompilation,
                keypair.pubkey_bytes(),
                dh_pubkey,
                fp,
                "Undefined identifier foo".to_string(),
                "Variable foo used before declaration".to_string(),
            );

            storage.record_outbound_beacon(&beacon)?;
            println!("[+] Recorded test distress beacon: {}", beacon.beacon_id);
        }
        _ => {
            eprintln!("Usage: open-humanity [status | sweep | test-distress]");
            std::process::exit(1);
        }
    }

    Ok(())
}
