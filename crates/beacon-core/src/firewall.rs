//! Deterministic Outbound Secrets and Personal Data Firewall.
//!
//! Enforces zero leakage of credentials, hardware tokens, API keys,
//! or absolute user directory paths across open-humanity beacons.

use regex::Regex;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum FirewallViolation {
    #[error("Detected AWS Access Key in beacon payload: {0}")]
    AwsKey(String),
    #[error("Detected GitHub Personal Access Token in beacon payload: {0}")]
    GitHubToken(String),
    #[error("Detected OpenAI API Key in beacon payload: {0}")]
    OpenAiKey(String),
    #[error("Detected Anthropic API Key in beacon payload: {0}")]
    AnthropicKey(String),
    #[error("Detected Google API Key in beacon payload: {0}")]
    GoogleApiKey(String),
    #[error("Detected Stripe API Key in beacon payload: {0}")]
    StripeKey(String),
    #[error("Detected HuggingFace Token in beacon payload: {0}")]
    HuggingFaceToken(String),
    #[error("Detected Private Key block in beacon payload")]
    PrivateKeyBlock,
    #[error("Detected generic high-entropy secret token: {0}")]
    GenericSecret(String),
    #[error("Detected relative path traversal attempt: {0}")]
    PathTraversal(String),
}

static AWS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"));

static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}").expect("valid regex"));

static OPENAI_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}").expect("valid regex"));

static ANTHROPIC_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").expect("valid regex"));

static GOOGLE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AIza[0-9A-Za-z_-]{30,}").expect("valid regex"));

static STRIPE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}").expect("valid regex"));

static HUGGINGFACE_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"hf_[a-zA-Z0-9]{34,}").expect("valid regex"));

static PRIVATE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").expect("valid regex"));

static GENERIC_SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:api_key|apikey|secret_key|private_key|auth_token|bearer)\s*[=:]\s*['"][A-Za-z0-9_\-+=/]{16,}['"]"#)
        .expect("valid regex")
});

static USER_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/(?:home|Users)/[A-Za-z0-9._-]+/").expect("valid regex"));

static WINDOWS_USER_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[a-z]:\\Users\\[A-Za-z0-9._-]+\\").expect("valid regex"));

static WINDOWS_USER_PATH_SLASH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[a-z]:/Users/[A-Za-z0-9._-]+/").expect("valid regex"));

static PATH_TRAVERSAL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\.[/\\])+").expect("valid regex"));

pub struct PersonalDataFirewall;

impl PersonalDataFirewall {
    pub fn verify_clean(text: &str) -> Result<(), FirewallViolation> {
        Self::scan_tokens(text)?;

        let normalized = Self::normalize_obfuscation(text);
        if normalized != text {
            Self::scan_tokens(&normalized)?;
        }

        let leet_normalized = Self::normalize_leetspeak(&normalized);
        if leet_normalized != normalized {
            if let Some(m) = GENERIC_SECRET_REGEX.find(&leet_normalized) {
                return Err(FirewallViolation::GenericSecret(m.as_str().to_string()));
            }
        }

        if PATH_TRAVERSAL_REGEX.is_match(text) || PATH_TRAVERSAL_REGEX.is_match(&normalized) {
            return Err(FirewallViolation::PathTraversal(
                "Detected relative path traversal attempt".to_string(),
            ));
        }

        Ok(())
    }

    fn scan_tokens(text: &str) -> Result<(), FirewallViolation> {
        if let Some(m) = AWS_KEY_REGEX.find(text) {
            return Err(FirewallViolation::AwsKey(m.as_str().to_string()));
        }

        if let Some(m) = GITHUB_TOKEN_REGEX.find(text) {
            return Err(FirewallViolation::GitHubToken(m.as_str().to_string()));
        }

        if let Some(m) = ANTHROPIC_KEY_REGEX.find(text) {
            return Err(FirewallViolation::AnthropicKey(m.as_str().to_string()));
        }

        if let Some(m) = OPENAI_KEY_REGEX.find(text) {
            return Err(FirewallViolation::OpenAiKey(m.as_str().to_string()));
        }

        if let Some(m) = GOOGLE_KEY_REGEX.find(text) {
            return Err(FirewallViolation::GoogleApiKey(m.as_str().to_string()));
        }

        if let Some(m) = STRIPE_KEY_REGEX.find(text) {
            return Err(FirewallViolation::StripeKey(m.as_str().to_string()));
        }

        if let Some(m) = HUGGINGFACE_TOKEN_REGEX.find(text) {
            return Err(FirewallViolation::HuggingFaceToken(m.as_str().to_string()));
        }

        if PRIVATE_KEY_REGEX.is_match(text) {
            return Err(FirewallViolation::PrivateKeyBlock);
        }

        if let Some(m) = GENERIC_SECRET_REGEX.find(text) {
            return Err(FirewallViolation::GenericSecret(m.as_str().to_string()));
        }

        Ok(())
    }

    pub fn redact_secrets(text: &str) -> String {
        let mut s = text.to_string();
        s = PRIVATE_KEY_REGEX.replace_all(&s, "[REDACTED_PRIVATE_KEY]").to_string();
        s = AWS_KEY_REGEX.replace_all(&s, "[REDACTED_AWS_KEY]").to_string();
        s = GITHUB_TOKEN_REGEX.replace_all(&s, "[REDACTED_GITHUB_TOKEN]").to_string();
        s = ANTHROPIC_KEY_REGEX.replace_all(&s, "[REDACTED_ANTHROPIC_KEY]").to_string();
        s = OPENAI_KEY_REGEX.replace_all(&s, "[REDACTED_OPENAI_KEY]").to_string();
        s = GOOGLE_KEY_REGEX.replace_all(&s, "[REDACTED_GOOGLE_KEY]").to_string();
        s = STRIPE_KEY_REGEX.replace_all(&s, "[REDACTED_STRIPE_KEY]").to_string();
        s = HUGGINGFACE_TOKEN_REGEX.replace_all(&s, "[REDACTED_HF_TOKEN]").to_string();
        s = GENERIC_SECRET_REGEX.replace_all(&s, "[REDACTED_GENERIC_SECRET]").to_string();
        s
    }

    pub fn sanitize_paths(text: &str) -> String {
        let s = WINDOWS_USER_PATH_REGEX.replace_all(text, "~\\");
        let s = WINDOWS_USER_PATH_SLASH_REGEX.replace_all(&s, "~/");
        let s = USER_PATH_REGEX.replace_all(&s, "~/");
        let s = PATH_TRAVERSAL_REGEX.replace_all(&s, "./");
        s.to_string()
    }

    pub fn normalize_obfuscation(text: &str) -> String {
        let stripped: String = text
            .chars()
            .filter(|c| {
                !matches!(
                    *c,
                    '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{00AD}'
                )
            })
            .collect();

        Self::decode_percent(&stripped)
    }

    pub fn decode_percent(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(val) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap_or_else(|_| input.to_string())
    }

    pub fn normalize_leetspeak(input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '0' => 'o',
                '1' | '!' => 'i',
                '3' => 'e',
                '4' | '@' => 'a',
                '5' | '$' => 's',
                '7' => 't',
                other => other,
            })
            .collect()
    }
}
