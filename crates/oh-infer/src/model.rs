//! Model verification on the volunteer: every weight file is checked
//! against the pinned manifest before the volunteer may serve.
//!
//! The manifest is the Sovereign Intelligence `model.manifest` format:
//! header lines `name <id>`, `url <url>`, `bytes <total>`, `files <count>`,
//! then one line per file, `<sha256 hex> <size> <relative path>`. The model
//! digest is the SHA-256 of the manifest bytes, so pinning the digest pins
//! every file's hash and size.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("cannot read {0}")]
    Unreadable(String),
    #[error("manifest is malformed: {0}")]
    Malformed(String),
    #[error("manifest digest {got} is not the pinned {expected}")]
    WrongManifest { expected: String, got: String },
    #[error("{path}: size {got}, manifest says {expected}")]
    WrongSize {
        path: String,
        expected: u64,
        got: u64,
    },
    #[error("{0}: SHA-256 does not match the manifest (modified or corrupt weights)")]
    WrongHash(String),
}

/// A verified model: its manifest name and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedModel {
    pub name: String,
    pub digest: [u8; 32],
    pub files: usize,
    pub bytes: u64,
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], ModelError> {
    let unreadable = || ModelError::Unreadable(path.display().to_string());
    let mut f = File::open(path).map_err(|_| unreadable())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|_| unreadable())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    oh_core::parse_key(s)
}

/// Checks `manifest_path` against `pinned` (if given), then every listed file
/// under `model_dir` for size and SHA-256. Refuses paths that leave the
/// model folder.
pub fn verify_model(
    manifest_path: &Path,
    model_dir: &Path,
    pinned: Option<&[u8; 32]>,
) -> Result<VerifiedModel, ModelError> {
    let bytes = std::fs::read(manifest_path)
        .map_err(|_| ModelError::Unreadable(manifest_path.display().to_string()))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if let Some(expected) = pinned {
        if &digest != expected {
            return Err(ModelError::WrongManifest {
                expected: crate::protocol::hex(expected),
                got: crate::protocol::hex(&digest),
            });
        }
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ModelError::Malformed("not UTF-8".into()))?;
    let mut name = None;
    let mut declared_files = None;
    let mut declared_bytes = None;
    let mut entries = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, ' ');
        let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let c = parts.next();
        match (a, c) {
            ("name", None) => name = Some(b.to_string()),
            ("url", None) => {}
            ("bytes", None) => declared_bytes = b.parse::<u64>().ok(),
            ("files", None) => declared_files = b.parse::<usize>().ok(),
            (sha, Some(path)) => {
                let sha = parse_hex32(sha)
                    .ok_or_else(|| ModelError::Malformed(format!("bad hash on line {line:?}")))?;
                let size = b
                    .parse::<u64>()
                    .map_err(|_| ModelError::Malformed(format!("bad size on line {line:?}")))?;
                let rel = Path::new(path);
                if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
                    return Err(ModelError::Malformed(format!(
                        "path {path:?} leaves the model folder"
                    )));
                }
                entries.push((sha, size, path.to_string()));
            }
            _ => return Err(ModelError::Malformed(format!("unknown line {line:?}"))),
        }
    }
    let name = name.ok_or_else(|| ModelError::Malformed("no name line".into()))?;
    let total: u64 = entries.iter().map(|e| e.1).sum();
    if declared_files != Some(entries.len()) || declared_bytes != Some(total) {
        return Err(ModelError::Malformed(
            "files or bytes line does not match the entries".into(),
        ));
    }
    for (sha, size, path) in &entries {
        let full = model_dir.join(path);
        let got = std::fs::metadata(&full)
            .map_err(|_| ModelError::Unreadable(full.display().to_string()))?
            .len();
        if got != *size {
            return Err(ModelError::WrongSize {
                path: path.clone(),
                expected: *size,
                got,
            });
        }
        if &sha256_file(&full)? != sha {
            return Err(ModelError::WrongHash(path.clone()));
        }
    }
    Ok(VerifiedModel {
        name,
        digest,
        files: entries.len(),
        bytes: total,
    })
}

/// Writes a manifest for the files in `dir` (test and packaging helper).
pub fn write_manifest(name: &str, dir: &Path, files: &[&str]) -> Result<Vec<u8>, ModelError> {
    let mut lines = String::new();
    let mut total = 0u64;
    for f in files {
        let p = dir.join(f);
        let size = std::fs::metadata(&p)
            .map_err(|_| ModelError::Unreadable(p.display().to_string()))?
            .len();
        total += size;
        lines.push_str(&format!(
            "{} {} {}\n",
            crate::protocol::hex(&sha256_file(&p)?),
            size,
            f
        ));
    }
    Ok(format!(
        "name {name}\nurl local\nbytes {total}\nfiles {}\n{lines}",
        files.len()
    )
    .into_bytes())
}
