//! Secret / credential detection (offline). Used on input (don't send secrets to
//! the model) and on output (don't let the model regurgitate credentials).
//! Pattern-based on known token shapes; generic high-entropy guessing is avoided
//! to keep false positives low.

use std::sync::LazyLock;

use regex::Regex;

use crate::types::{Finding, Risk};

struct Pat {
    re: Regex,
    type_: &'static str,
    risk: Risk,
}

static PATTERNS: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    let p = |re: &str, type_: &'static str, risk: Risk| Pat {
        re: Regex::new(re).unwrap(),
        type_,
        risk,
    };
    vec![
        p(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            "private_key",
            Risk::Critical,
        ),
        p(
            r"\b(?:sk|rk|pk)_live_[A-Za-z0-9]{16,}\b",
            "stripe_key",
            Risk::Critical,
        ),
        p(
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            "openai_api_key",
            Risk::High,
        ),
        p(r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key_id", Risk::High),
        p(
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
            "github_token",
            Risk::High,
        ),
        p(
            r"\bgithub_pat_[A-Za-z0-9_]{60,}\b",
            "github_token",
            Risk::High,
        ),
        p(r"\bAIza[0-9A-Za-z_\-]{35}\b", "google_api_key", Risk::High),
        p(
            r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
            "slack_token",
            Risk::High,
        ),
        p(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            "jwt",
            Risk::Medium,
        ),
    ]
});

fn scan_labeled(text: &str, scanner: &str, detail: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for p in PATTERNS.iter() {
        for m in p.re.find_iter(text) {
            findings.push(Finding::new(
                scanner,
                p.type_,
                p.risk,
                Some([m.start(), m.end()]),
                detail,
            ));
        }
    }
    findings
}

/// Scan input `text` for secrets the user should not send to the model.
pub fn scan(text: &str) -> Vec<Finding> {
    scan_labeled(text, "secrets", "credential/secret in input")
}

/// Scan model output for secrets the model should not regurgitate (`secretLeak`).
pub fn scan_leak(text: &str) -> Vec<Finding> {
    scan_labeled(text, "secretLeak", "credential/secret leaked in output")
}
