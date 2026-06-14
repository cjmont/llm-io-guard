//! Prompt-injection / jailbreak heuristics (offline, best-effort).
//!
//! IMPORTANT: prompt injection is an open problem; this is defense-in-depth with
//! false negatives, never a guarantee. Detection is tunable by sensitivity:
//! `Low` = only high-confidence known patterns; `Medium` = + common heuristics;
//! `High` = aggressive (more recall, more false positives).

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::types::{Finding, Risk};

/// Detection sensitivity, ordered `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

struct Pat {
    text: &'static str,
    type_: &'static str,
    risk: Risk,
    min: Sensitivity,
}

// Known phrase patterns (matched case-insensitively).
const PATTERNS: &[Pat] = &[
    Pat {
        text: "ignore previous instructions",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "ignore all previous",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "ignore the above",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "disregard previous",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "disregard the above",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "forget everything",
        type_: "instruction_override",
        risk: Risk::High,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "new instructions:",
        type_: "instruction_override",
        risk: Risk::Medium,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "do anything now",
        type_: "jailbreak",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "jailbreak",
        type_: "jailbreak",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "developer mode",
        type_: "jailbreak",
        risk: Risk::Medium,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "without any restrictions",
        type_: "jailbreak",
        risk: Risk::Medium,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "you are now",
        type_: "role_manipulation",
        risk: Risk::Medium,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "pretend you are",
        type_: "role_manipulation",
        risk: Risk::Medium,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "reveal your system prompt",
        type_: "prompt_leak",
        risk: Risk::High,
        min: Sensitivity::Low,
    },
    Pat {
        text: "print your instructions",
        type_: "prompt_leak",
        risk: Risk::High,
        min: Sensitivity::Medium,
    },
    Pat {
        text: "system prompt",
        type_: "prompt_leak",
        risk: Risk::Low,
        min: Sensitivity::High,
    },
    // generic, only at high sensitivity (noisy)
    Pat {
        text: "bypass",
        type_: "jailbreak",
        risk: Risk::Low,
        min: Sensitivity::High,
    },
    Pat {
        text: "act as",
        type_: "role_manipulation",
        risk: Risk::Low,
        min: Sensitivity::High,
    },
];

static AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(PATTERNS.iter().map(|p| p.text))
        .unwrap()
});

// Structural patterns (fake chat delimiters / role injection / obfuscation).
static RE_DELIMITER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\|im_(?:start|end)\|>|\[/?INST\]|<</?SYS>>|###\s*(?:system|instruction)|^\s*(?:system|assistant)\s*:")
        .unwrap()
});
static RE_BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap());
// Zero-width / bidi obfuscation characters.
static RE_INVISIBLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\u{200B}-\u{200F}\u{202A}-\u{202E}\u{2060}\u{FEFF}]").unwrap());

/// Scan `text` for prompt-injection signals at the given `sensitivity`.
pub fn scan(text: &str, sensitivity: Sensitivity) -> Vec<Finding> {
    let mut findings = Vec::new();

    for m in AC.find_iter(text) {
        let p = &PATTERNS[m.pattern().as_usize()];
        if sensitivity >= p.min {
            findings.push(Finding::new(
                "promptInjection",
                p.type_,
                p.risk,
                Some([m.start(), m.end()]),
                "known prompt-injection pattern (heuristic, best-effort)",
            ));
        }
    }

    for m in RE_DELIMITER.find_iter(text) {
        findings.push(Finding::new(
            "promptInjection",
            "fake_delimiter",
            Risk::High,
            Some([m.start(), m.end()]),
            "fake chat/role delimiter — possible injection",
        ));
    }

    for m in RE_INVISIBLE.find_iter(text) {
        findings.push(Finding::new(
            "promptInjection",
            "obfuscation",
            Risk::Medium,
            Some([m.start(), m.end()]),
            "invisible/bidi character — possible obfuscated injection",
        ));
    }

    if sensitivity >= Sensitivity::Medium {
        for m in RE_BASE64.find_iter(text) {
            findings.push(Finding::new(
                "promptInjection",
                "encoding_obfuscation",
                Risk::Medium,
                Some([m.start(), m.end()]),
                "long base64-like blob — possible encoded payload",
            ));
        }
    }

    findings
}
