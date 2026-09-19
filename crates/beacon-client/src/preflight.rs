//! Autonomous Sandboxed Preflight Verification.
//!
//! Applies candidate resolution patches inside an ephemeral, isolated
//! directory (/tmp/beacon-verify-<uuid>), executing compiler verification
//! before any changes touch active workspaces.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum PreflightError {
    #[error("IO error during preflight setup: {0}")]
    Io(#[from] std::io::Error),
    #[error("Verification command failed with status {status}: {stderr}")]
    VerificationFailed { status: i32, stderr: String },
    #[error("Failed to execute verification command: {0}")]
    Execution(String),
}

#[derive(Debug)]
pub struct PreflightReceipt {
    pub passed: bool,
    pub stdout: String,
    pub stderr: String,
}

pub struct PreflightSandbox {
    pub sandbox_path: PathBuf,
}

impl PreflightSandbox {
    pub fn new() -> Result<Self, PreflightError> {
        let id = Uuid::now_v7();
        let sandbox_path = std::env::temp_dir().join(format!("beacon-verify-{}", id));
        fs::create_dir_all(&sandbox_path)?;
        Ok(Self { sandbox_path })
    }

    pub fn path(&self) -> &Path {
        &self.sandbox_path
    }

    pub fn write_file(&self, relative_path: &str, content: &str) -> Result<PathBuf, PreflightError> {
        let target = self.sandbox_path.join(relative_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, content)?;
        Ok(target)
    }

    pub fn run_check(&self, program: &str, args: &[&str]) -> Result<PreflightReceipt, PreflightError> {
        let output = Command::new(program)
            .args(args)
            .current_dir(&self.sandbox_path)
            .output()
            .map_err(|e| PreflightError::Execution(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() {
            Ok(PreflightReceipt {
                passed: true,
                stdout,
                stderr,
            })
        } else {
            Err(PreflightError::VerificationFailed {
                status: output.status.code().unwrap_or(-1),
                stderr,
            })
        }
    }
}

impl Drop for PreflightSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.sandbox_path);
    }
}
