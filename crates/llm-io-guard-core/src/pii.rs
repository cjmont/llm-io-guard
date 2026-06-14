//! Structured PII detection and reversible redaction.
//!
//! High-precision, offline, rule-based detection of *structured* PII (validated
//! with Luhn / IBAN mod-97 / DNI checksum where applicable). Free-form PII such
//! as names and addresses needs an optional NER model (the `nerHook` documented
//! in the TS layer) — the rule core does not attempt them.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{Finding, RedactResult, Risk, Vault};

/// PII entity kinds covered by the offline rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Entity {
    Email,
    Phone,
    CreditCard,
    Iban,
    Ip,
    UsSsn,
    EsDni,
}

impl Entity {
    fn label(self) -> &'static str {
        match self {
            Entity::Email => "EMAIL",
            Entity::Phone => "PHONE",
            Entity::CreditCard => "CARD",
            Entity::Iban => "IBAN",
            Entity::Ip => "IP",
            Entity::UsSsn => "SSN",
            Entity::EsDni => "DNI",
        }
    }
    fn risk(self) -> Risk {
        match self {
            Entity::CreditCard | Entity::Iban | Entity::UsSsn | Entity::EsDni => Risk::High,
            _ => Risk::Medium,
        }
    }
    /// Priority for overlap resolution (higher wins).
    fn priority(self) -> u8 {
        match self {
            Entity::Iban => 6,
            Entity::CreditCard => 5,
            Entity::UsSsn => 4,
            Entity::EsDni => 3,
            Entity::Email => 2,
            Entity::Ip => 1,
            Entity::Phone => 0,
        }
    }
}

/// The default fintech/GDPR entity set.
pub const DEFAULT_ENTITIES: [Entity; 7] = [
    Entity::Email,
    Entity::Phone,
    Entity::CreditCard,
    Entity::Iban,
    Entity::Ip,
    Entity::UsSsn,
    Entity::EsDni,
];

/// Redaction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Replace with a stable placeholder and record it in the vault (reversible).
    Replace,
    /// Partially mask, keeping a few characters (not reversible).
    Mask,
    /// Replace with a deterministic non-cryptographic hash token (not reversible).
    Hash,
}

static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap());
static RE_IBAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap());
static RE_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap());
static RE_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static RE_SSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static RE_DNI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:[XYZ]\d{7}|\d{8})[A-Z]\b").unwrap());
static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\+?\d[\d\s().\-]{6,}\d").unwrap());

#[derive(Clone)]
struct Match {
    start: usize,
    end: usize,
    kind: Entity,
    value: String,
}

fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut d = d;
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

fn iban_ok(s: &str) -> bool {
    let s = s.to_ascii_uppercase();
    if s.len() < 15 {
        return false;
    }
    let (head, tail) = s.split_at(4);
    let mut rem: u32 = 0;
    for c in tail.chars().chain(head.chars()) {
        let val = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else if c.is_ascii_alphabetic() {
            c as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        if val >= 10 {
            rem = (rem * 100 + val) % 97;
        } else {
            rem = (rem * 10 + val) % 97;
        }
    }
    rem == 1
}

fn ip_ok(s: &str) -> bool {
    s.split('.').all(|o| o.parse::<u8>().is_ok()) && s.split('.').count() == 4
}

fn ssn_ok(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    if p.len() != 3 {
        return false;
    }
    let area = p[0];
    area != "000" && area != "666" && !area.starts_with('9') && p[1] != "00" && p[2] != "0000"
}

fn dni_ok(s: &str) -> bool {
    const LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let s = s.to_ascii_uppercase();
    let bytes = s.as_bytes();
    let letter = *bytes.last().unwrap();
    let num_part = &s[..s.len() - 1];
    let numeric: String = num_part
        .chars()
        .map(|c| match c {
            'X' => '0',
            'Y' => '1',
            'Z' => '2',
            other => other,
        })
        .collect();
    let n: u32 = match numeric.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    LETTERS[(n % 23) as usize] == letter
}

fn collect(text: &str, entities: &[Entity]) -> Vec<Match> {
    let mut out = Vec::new();
    let push = |re: &Regex, kind: Entity, valid: &dyn Fn(&str) -> bool, out: &mut Vec<Match>| {
        for m in re.find_iter(text) {
            if valid(m.as_str()) {
                out.push(Match {
                    start: m.start(),
                    end: m.end(),
                    kind,
                    value: m.as_str().to_string(),
                });
            }
        }
    };
    for &e in entities {
        match e {
            Entity::Email => push(&RE_EMAIL, e, &|_| true, &mut out),
            Entity::Iban => push(&RE_IBAN, e, &iban_ok, &mut out),
            Entity::CreditCard => push(&RE_CARD, e, &luhn_ok, &mut out),
            Entity::Ip => push(&RE_IP, e, &ip_ok, &mut out),
            Entity::UsSsn => push(&RE_SSN, e, &ssn_ok, &mut out),
            Entity::EsDni => push(&RE_DNI, e, &dni_ok, &mut out),
            Entity::Phone => push(
                &RE_PHONE,
                e,
                &|s| s.chars().filter(|c| c.is_ascii_digit()).count() >= 7,
                &mut out,
            ),
        }
    }
    // Resolve overlaps: prefer earlier start, then higher priority, then longer.
    out.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.kind.priority().cmp(&a.kind.priority()))
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut chosen = Vec::new();
    let mut last_end = 0usize;
    for m in out {
        if m.start >= last_end {
            last_end = m.end;
            chosen.push(m);
        }
    }
    chosen
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn mask(value: &str, kind: Entity) -> String {
    if kind == Entity::CreditCard {
        let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
        let last4 = &digits[digits.len().saturating_sub(4)..];
        return format!("****{last4}");
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    format!(
        "{}{}{}",
        chars[0],
        "*".repeat(chars.len() - 2),
        chars[chars.len() - 1]
    )
}

/// Detect PII without modifying the text.
pub fn scan(text: &str, entities: &[Entity]) -> Vec<Finding> {
    collect(text, entities)
        .iter()
        .map(|m| {
            Finding::new(
                "piiRedact",
                m.kind.label(),
                m.kind.risk(),
                Some([m.start, m.end]),
                "structured PII detected",
            )
        })
        .collect()
}

/// Redact PII. In `Replace` mode the returned `vault` maps each placeholder back
/// to its original value (reversible via [`restore`]).
pub fn redact(text: &str, entities: &[Entity], mode: Mode) -> RedactResult {
    let chosen = collect(text, entities);
    let mut vault: Vault = Vault::new();
    let mut counters: HashMap<Entity, usize> = HashMap::new();
    let mut value_to_ph: HashMap<(Entity, String), String> = HashMap::new();
    let mut findings = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;

    for m in &chosen {
        out.push_str(&text[cursor..m.start]);
        let replacement = match mode {
            Mode::Replace => {
                let key = (m.kind, m.value.clone());
                let ph = value_to_ph.entry(key).or_insert_with(|| {
                    let n = counters.entry(m.kind).or_insert(0);
                    *n += 1;
                    let ph = format!("[PII_{}_{}]", m.kind.label(), n);
                    vault.insert(ph.clone(), m.value.clone());
                    ph
                });
                ph.clone()
            }
            Mode::Mask => mask(&m.value, m.kind),
            Mode::Hash => format!("[PII_{}_{:016x}]", m.kind.label(), fnv1a(&m.value)),
        };
        out.push_str(&replacement);
        cursor = m.end;
        findings.push(Finding::new(
            "piiRedact",
            m.kind.label(),
            m.kind.risk(),
            Some([m.start, m.end]),
            "structured PII redacted",
        ));
    }
    out.push_str(&text[cursor..]);

    RedactResult {
        sanitized: out,
        vault,
        findings,
    }
}

/// Restore placeholders in `text` back to their original values using `vault`.
pub fn restore(text: &str, vault: &Vault) -> String {
    let mut out = text.to_string();
    // Replace longer placeholders first to avoid prefix collisions.
    let mut keys: Vec<&String> = vault.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for k in keys {
        if let Some(v) = vault.get(k) {
            out = out.replace(k, v);
        }
    }
    out
}
