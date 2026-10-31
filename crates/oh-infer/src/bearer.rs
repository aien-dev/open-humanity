//! The local engine's per-install bearer token.
//!
//! Engines built from Sovereign Intelligence Core main refuse a request
//! without `Authorization: Bearer <token>`. The SI wizard (DRA-56) keeps the
//! token at `~/.local/share/aienos/auth/bearer-token` and hands it to the
//! engine as `AIEN_SERVE_HTTP_BEARER_TOKEN`. The volunteer reads the same file
//! and makes the same checks the wizard makes (`installer/wizard/net.om`,
//! `tkload`): the folder is a real folder of this user with mode 0700, the
//! file is a regular file of this user with mode 0600, neither is a link, and
//! the file is exactly 64 lowercase hex digits and a newline.
//!
//! The token is never printed: its `Debug` form is redacted, errors name
//! only the path and the failed check, and the bytes are zeroed on drop.

use std::fmt;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Where the SI wizard writes the token, relative to `$HOME`.
pub const TOKEN_HOME_PATH: &str = ".local/share/aienos/auth/bearer-token";

const TOKEN_HEX: usize = 64;

/// 64 lowercase hex digits, the value sent after `Bearer `.
#[derive(Clone)]
pub struct BearerToken([u8; TOKEN_HEX]);

impl BearerToken {
    /// The header value's token part. Always ASCII hex.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("checked to be ASCII hex on load")
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("{0}")]
    NotPrivate(String),
    #[error("{0} is not 64 lowercase hex digits and a newline")]
    Malformed(String),
    #[error("{0}: {1}")]
    Io(String, String),
}

/// `$HOME/.local/share/aienos/auth/bearer-token`, or `None` without `$HOME`.
pub fn default_token_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(TOKEN_HOME_PATH))
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `what` (a folder or file at `path`) must be this user's, not a link, of
/// the expected kind, with exactly the permission bits `mode`.
fn check_private(path: &Path, m: &Metadata, dir: bool, mode: u32) -> Result<(), TokenError> {
    let shown = path.display();
    let kind = if dir { "folder" } else { "file" };
    let ft = m.file_type();
    if ft.is_symlink() {
        return Err(TokenError::NotPrivate(format!(
            "{shown} is a link; the token {kind} must be a real {kind}"
        )));
    }
    if (dir && !ft.is_dir()) || (!dir && !ft.is_file()) {
        return Err(TokenError::NotPrivate(format!("{shown} is not a {kind}")));
    }
    if m.uid() != euid() {
        return Err(TokenError::NotPrivate(format!(
            "{shown} belongs to uid {}, not to this user",
            m.uid()
        )));
    }
    let bits = m.mode() & 0o7777;
    if bits != mode {
        return Err(TokenError::NotPrivate(format!(
            "{shown} has mode {bits:04o}; it must be {mode:04o} (run: chmod {mode:o} {shown})"
        )));
    }
    Ok(())
}

/// Loads the token at `path`.
///
/// `Ok(None)` when there is no file there: the shipped engine needs no
/// token, so the caller sends none. An existing file that fails any check is
/// an error, never silently skipped.
pub fn load_bearer_token(path: &Path) -> Result<Option<BearerToken>, TokenError> {
    let io = |e: std::io::Error| TokenError::Io(path.display().to_string(), e.to_string());
    let fm = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dm = std::fs::symlink_metadata(dir)
        .map_err(|e| TokenError::Io(dir.display().to_string(), e.to_string()))?;
    check_private(dir, &dm, true, 0o700)?;
    check_private(path, &fm, false, 0o600)?;
    if fm.len() != TOKEN_HEX as u64 + 1 {
        return Err(TokenError::Malformed(path.display().to_string()));
    }
    let mut f = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    // The file read is the one that was checked, not one swapped in since.
    let om = f.metadata().map_err(io)?;
    if om.dev() != fm.dev() || om.ino() != fm.ino() {
        return Err(TokenError::NotPrivate(format!(
            "{} changed while it was being checked",
            path.display()
        )));
    }
    let mut buf = [0u8; TOKEN_HEX + 2];
    let mut n = 0;
    loop {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if n == buf.len() {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                buf.fill(0);
                return Err(io(e));
            }
        }
    }
    let ok = n == TOKEN_HEX + 1
        && buf[TOKEN_HEX] == b'\n'
        && buf[..TOKEN_HEX]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
    let mut tok = [0u8; TOKEN_HEX];
    if ok {
        tok.copy_from_slice(&buf[..TOKEN_HEX]);
    }
    buf.fill(0);
    if !ok {
        return Err(TokenError::Malformed(path.display().to_string()));
    }
    Ok(Some(BearerToken(tok)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const GOOD: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A temp root with `auth/` (mode `dmode`) holding `bearer-token` (mode
    /// `fmode`) with `text`. Returns the root guard and the file path.
    fn setup(text: &[u8], dmode: u32, fmode: u32) -> (Tmp, PathBuf) {
        use rand::RngCore;
        let root = std::env::temp_dir().join(format!(
            "oh-infer-bearer-{}-{}",
            std::process::id(),
            rand::thread_rng().next_u64()
        ));
        let dir = root.join("auth");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bearer-token");
        std::fs::write(&file, text).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(fmode)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(dmode)).unwrap();
        (Tmp(root), file)
    }

    #[test]
    fn loads_the_wizards_file() {
        let (_t, f) = setup(GOOD.as_bytes(), 0o700, 0o600);
        let tok = load_bearer_token(&f).unwrap().unwrap();
        assert_eq!(tok.as_str(), GOOD.trim_end());
    }

    #[test]
    fn missing_file_is_no_token() {
        let (_t, f) = setup(GOOD.as_bytes(), 0o700, 0o600);
        assert_eq!(
            load_bearer_token(&f.with_file_name("absent"))
                .unwrap()
                .map(|_| ()),
            None
        );
        assert!(
            load_bearer_token(Path::new("/nonexistent-oh-infer/auth/bearer-token"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn refuses_a_file_others_can_read() {
        for mode in [0o644, 0o640, 0o604, 0o400, 0o660] {
            let (_t, f) = setup(GOOD.as_bytes(), 0o700, mode);
            let e = load_bearer_token(&f).unwrap_err();
            assert!(matches!(e, TokenError::NotPrivate(_)), "{mode:o}: {e:?}");
            assert!(!e.to_string().contains(GOOD.trim_end()));
        }
    }

    #[test]
    fn refuses_a_folder_others_can_enter() {
        for mode in [0o755, 0o750, 0o711] {
            let (_t, f) = setup(GOOD.as_bytes(), mode, 0o600);
            assert!(matches!(
                load_bearer_token(&f),
                Err(TokenError::NotPrivate(_))
            ));
        }
    }

    #[test]
    fn refuses_malformed_contents() {
        let upper = GOOD.to_uppercase();
        let no_nl = &GOOD[..64];
        let short = &GOOD[2..];
        let crlf = format!("{}\r\n", &GOOD[..63]);
        let extra = format!("{GOOD}\n");
        let nonhex = format!("{}g\n", &GOOD[..63]);
        for text in [&upper[..], no_nl, short, &crlf, &extra, &nonhex, ""] {
            let (_t, f) = setup(text.as_bytes(), 0o700, 0o600);
            let e = load_bearer_token(&f).unwrap_err();
            assert!(matches!(e, TokenError::Malformed(_)), "{text:?}: {e:?}");
        }
    }

    #[test]
    fn refuses_a_link() {
        let (_t, f) = setup(GOOD.as_bytes(), 0o700, 0o600);
        let link = f.with_file_name("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(matches!(
            load_bearer_token(&link),
            Err(TokenError::NotPrivate(_))
        ));
    }

    #[test]
    fn debug_never_shows_the_token() {
        let (_t, f) = setup(GOOD.as_bytes(), 0o700, 0o600);
        let tok = load_bearer_token(&f).unwrap().unwrap();
        let shown = format!("{tok:?}");
        assert!(!shown.contains(&GOOD[..16]), "{shown}");
    }
}
