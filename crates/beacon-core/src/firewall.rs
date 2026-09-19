//! Deterministic Outbound Secrets and Personal Data Firewall.
//!
//! Enforces zero leakage of credentials, hardware tokens, API keys,
//! or absolute user directory paths across open-humanity beacons.

use regex::Regex;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FirewallViolation {
    #[error("Detected AWS Access Key in beacon payload: {0}")]
    AwsKey(String),
    #[error("Detected GitHub Personal Access Token in beacon payload: {0}")]
    GitHubToken(String),
    #[error("Detected OpenAI API Key in beacon payload: {0}")]
    OpenAiKey(String),
    #[error("Detected Anthropic API Key in beacon payload: {0}")]
    AnthropicKey(String),
    #[error("Detected Private Key block in beacon payload")]
    PrivateKeyBlock,
    #[error("Detected generic high-entropy secret token: {0}")]
    GenericSecret(String),
}

static AWS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"));

static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}").expect("valid regex"));

static OPENAI_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}").expect("valid regex"));

static ANTHROPIC_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{32,}").expect("valid regex"));

static PRIVATE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").expect("valid regex"));

static GENERIC_SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:api_key|apikey|secret_key|private_key|auth_token|bearer)\s*[=:]\s*['"][A-Za-z0-9_\-+=/]{16,}['"]"#)
        .expect("valid regex")
});

static USER_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/(?:home|Users)/[A-Za-z0-9._-]+/").expect("valid regex"));

pub struct PersonalDataFirewall;

impl PersonalDataFirewall {
    pub fn verify_clean(text: &str) -> Result<(), FirewallViolation> {
        if let Some(m) = AWS_KEY_REGEX.find(text) {
            return Err(FirewallViolation::AwsKey(m.as_str().to_string()));
        }

        if let Some(m) = GITHUB_TOKEN_REGEX.find(text) {
            return Err(FirewallViolation::GitHubToken(m.as_str().to_string()));
        }

        if let Some(m) = OPENAI_KEY_REGEX.find(text) {
            return Err(FirewallViolation::OpenAiKey(m.as_str().to_string()));
        }

        if let Some(m) = ANTHROPIC_KEY_REGEX.find(text) {
            return Err(FirewallViolation::AnthropicKey(m.as_str().to_string()));
        }

        if PRIVATE_KEY_REGEX.is_match(text) {
            return Err(FirewallViolation::PrivateKeyBlock);
        }

        if let Some(m) = GENERIC_SECRET_REGEX.find(text) {
            return Err(FirewallViolation::GenericSecret(m.as_str().to_string()));
        }

        Ok(())
    }

    pub fn sanitize_paths(text: &str) -> String {
        USER_PATH_REGEX.replace_all(text, "~/").to_string()
    }
}
