//! Shared coordinator and volunteer Ed25519 identity from atlas-vault.
//!
//! A 32-byte secret seed is read into memory from `atlas-vault get <NAME>`,
//! converted into a signing key, and wiped. The seed is never written to
//! disk, printed, or logged, and errors never quote it.
use beacon_core::Keypair;
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroize;

/// Parses 64 hex characters into a 32-byte key.
pub fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Rebuilds the key from the vault's output: exactly 64 hex characters
/// (one 32-byte seed), surrounding whitespace allowed. Errors never include
/// any of the input.
pub fn keypair_from_seed_hex(text: &[u8]) -> Result<Keypair, String> {
    let start = text.iter().position(|b| !b.is_ascii_whitespace());
    let end = text.iter().rposition(|b| !b.is_ascii_whitespace());
    let trimmed = match (start, end) {
        (Some(s), Some(e)) => &text[s..=e],
        _ => &[][..],
    };
    let bad = || "key seed must be exactly 64 hex characters (32 bytes)".to_string();
    if trimmed.len() != 64 {
        return Err(bad());
    }
    let mut seed = [0u8; 32];
    for (i, pair) in trimmed.chunks(2).enumerate() {
        match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Some(hi), Some(lo)) => seed[i] = hi << 4 | lo,
            _ => {
                seed.zeroize();
                return Err(bad());
            }
        }
    }
    let keypair = Keypair::from_seed(&seed);
    seed.zeroize();
    Ok(keypair)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Runs `<vault_bin> get <name>` and rebuilds the key from its stdout. The
/// vault's stdin and stderr are passed through so it can ask for a PIN or
/// report its own errors; its stdout (the secret) is only held in memory and
/// wiped after use.
pub fn keypair_from_vault(vault_bin: &Path, name: &str) -> Result<Keypair, String> {
    if name.is_empty() || name.starts_with('-') {
        return Err(format!("bad vault key name {name:?}"));
    }
    let mut out = Command::new(vault_bin)
        .arg("get")
        .arg(name)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", vault_bin.display()))?;
    let result = if out.status.success() {
        keypair_from_seed_hex(&out.stdout)
            .map_err(|e| format!("vault entry {name:?} is not an identity key: {e}"))
    } else {
        Err(format!(
            "{} get {name:?} failed ({})",
            vault_bin.display(),
            out.status
        ))
    };
    out.stdout.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn seed() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn test_seed_hex_gives_the_same_key_every_time() {
        let want = Keypair::from_seed(&seed()).pubkey_bytes();
        let a = keypair_from_seed_hex(SEED_HEX.as_bytes()).unwrap();
        let b =
            keypair_from_seed_hex(format!("  {}\n", SEED_HEX.to_uppercase()).as_bytes()).unwrap();
        assert_eq!(a.pubkey_bytes(), want);
        assert_eq!(b.pubkey_bytes(), want);
    }

    #[test]
    fn test_bad_seed_is_refused_without_echoing_it() {
        for bad in [
            "",
            "\n",
            &SEED_HEX[..62],
            &format!("{SEED_HEX}00"),
            &format!("{}zz", &SEED_HEX[..62]),
            &format!("{} {}", &SEED_HEX[..32], &SEED_HEX[32..]),
        ] {
            let err = keypair_from_seed_hex(bad.as_bytes()).err().unwrap();
            assert!(!err.contains("0102030405"), "error quotes the input: {err}");
        }
    }

    #[test]
    fn test_vault_that_cannot_run_or_fails_is_an_error() {
        let missing = keypair_from_vault(Path::new("/nonexistent/atlas-vault"), "k");
        assert!(missing.err().unwrap().contains("cannot run"));
        let failing = keypair_from_vault(Path::new("/bin/false"), "k");
        assert!(failing.err().unwrap().contains("failed"));
        assert!(keypair_from_vault(Path::new("/bin/false"), "--help").is_err());
    }

    #[test]
    fn test_vault_stdout_becomes_the_key() {
        // A stand-in vault: a shell script that answers `get oh-test-key`
        // with the seed and refuses anything else.
        let dir = std::env::temp_dir().join(format!("oh-vault-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("atlas-vault");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\n[ \"$1\" = get ] && [ \"$2\" = oh-test-key ] || exit 3\necho {SEED_HEX}\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();

        let key = keypair_from_vault(&bin, "oh-test-key").unwrap();
        assert_eq!(
            key.pubkey_bytes(),
            Keypair::from_seed(&seed()).pubkey_bytes()
        );
        let err = keypair_from_vault(&bin, "other").err().unwrap();
        assert!(err.contains("failed"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
