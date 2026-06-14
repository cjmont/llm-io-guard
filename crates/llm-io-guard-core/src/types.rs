//! Shared result types. Every operation returns a rich result, never a bare
//! boolean. We fail closed on ambiguity.

use serde::Serialize;
use std::collections::BTreeMap;

/// Risk level, ordered `None < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A single detection. `span` is a byte range into the scanned UTF-8 string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub scanner: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub risk: Risk,
    pub span: Option<[usize; 2]>,
    pub detail: String,
}

impl Finding {
    pub fn new(
        scanner: &str,
        type_: &str,
        risk: Risk,
        span: Option<[usize; 2]>,
        detail: &str,
    ) -> Self {
        Finding {
            scanner: scanner.to_string(),
            type_: type_.to_string(),
            risk,
            span,
            detail: detail.to_string(),
        }
    }
}

/// Maps a stable placeholder (e.g. `[PII_EMAIL_1]`) to the original value.
/// Lives only in process memory; never persisted by this library.
pub type Vault = BTreeMap<String, String>;

/// Result of a redaction pass.
#[derive(Debug, Clone, Serialize)]
pub struct RedactResult {
    pub sanitized: String,
    pub vault: Vault,
    pub findings: Vec<Finding>,
}

/// Maximum severity across a set of findings.
pub fn max_risk(findings: &[Finding]) -> Risk {
    findings.iter().map(|f| f.risk).max().unwrap_or(Risk::None)
}
