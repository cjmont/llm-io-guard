//! Package-name extraction for the `packageHallucination` scanner.
//!
//! The core only EXTRACTS candidate package names from install commands (offline);
//! verifying whether they exist against a registry requires network and lives in
//! the TS layer (opt-in, with graceful degradation). This keeps the core offline.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
    Crates,
    Pub,
    Rubygems,
}

impl Ecosystem {
    fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Crates => "crates",
            Ecosystem::Pub => "pub",
            Ecosystem::Rubygems => "rubygems",
        }
    }
    fn command_re(self) -> &'static Regex {
        match self {
            Ecosystem::Npm => &RE_NPM,
            Ecosystem::Pypi => &RE_PYPI,
            Ecosystem::Crates => &RE_CRATES,
            Ecosystem::Pub => &RE_PUB,
            Ecosystem::Rubygems => &RE_GEM,
        }
    }
}

/// A candidate package reference extracted from text (not yet verified).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageRef {
    pub ecosystem: String,
    pub name: String,
    pub span: [usize; 2],
}

pub const DEFAULT_ECOSYSTEMS: [Ecosystem; 5] = [
    Ecosystem::Npm,
    Ecosystem::Pypi,
    Ecosystem::Crates,
    Ecosystem::Pub,
    Ecosystem::Rubygems,
];

static RE_NPM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:npm (?:i|install|add)|yarn add|pnpm (?:i|install|add))\b").unwrap()
});
static RE_PYPI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:pip3?|python -m pip) install\b").unwrap());
static RE_CRATES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcargo (?:add|install)\b").unwrap());
static RE_PUB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:dart|flutter) pub add\b").unwrap());
static RE_GEM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bgem install\b").unwrap());

static RE_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\S+").unwrap());

/// Strip a version specifier from a token, returning the bare package name.
fn clean_name(eco: Ecosystem, token: &str) -> Option<String> {
    // strip wrapping punctuation (backticks, quotes, parens, commas)
    let token = token.trim_matches(|c: char| matches!(c, '`' | '\'' | '"' | '(' | ')' | ',' | ';'));
    if token.is_empty() || token.starts_with('-') {
        return None; // flag or empty
    }
    let name = match eco {
        Ecosystem::Npm => {
            if let Some(rest) = token.strip_prefix('@') {
                // scoped: @scope/name[@version]
                rest.split_once('@')
                    .map(|(s, _)| format!("@{s}"))
                    .unwrap_or_else(|| token.to_string())
            } else {
                token.split('@').next().unwrap_or(token).to_string()
            }
        }
        Ecosystem::Pypi => token
            .split(['=', '<', '>', '~', '!', '['])
            .next()
            .unwrap_or(token)
            .to_string(),
        _ => token
            .split(['@', '=', ':'])
            .next()
            .unwrap_or(token)
            .to_string(),
    };
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@'));
    if ok {
        Some(name)
    } else {
        None
    }
}

/// Extract candidate package references from `text`.
pub fn extract(text: &str, ecosystems: &[Ecosystem]) -> Vec<PackageRef> {
    let mut out = Vec::new();
    for &eco in ecosystems {
        for cmd in eco.command_re().find_iter(text) {
            // names live on the rest of the command's line
            let rest_start = cmd.end();
            let line_end = text[rest_start..]
                .find('\n')
                .map(|i| rest_start + i)
                .unwrap_or(text.len());
            let region = &text[rest_start..line_end];

            for tok in RE_TOKEN.find_iter(region) {
                let raw = tok.as_str();
                // stop at a shell separator
                if matches!(raw, "&&" | "||" | ";" | "|" | ">" | ">>") {
                    break;
                }
                if let Some(name) = clean_name(eco, raw) {
                    out.push(PackageRef {
                        ecosystem: eco.label().to_string(),
                        name,
                        span: [rest_start + tok.start(), rest_start + tok.end()],
                    });
                }
            }
        }
    }
    out
}
