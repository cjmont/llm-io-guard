//! Offline malicious-URL heuristics: IDN homographs, typosquatting of popular
//! brands, suspicious TLDs, IP-host URLs, and userinfo (`user@host`) tricks.
//! Heuristic and best-effort — an optional allow/deny list belongs in the TS layer.

use std::sync::LazyLock;

use regex::Regex;

use crate::types::{Finding, Risk};

static RE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"')\]]+"#).unwrap());

const BRANDS: &[&str] = &[
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "github",
    "binance",
    "metamask",
    "coinbase",
    "netflix",
    "whatsapp",
    "instagram",
];

const SUSPICIOUS_TLDS: &[&str] = &[
    ".zip", ".mov", ".xyz", ".top", ".click", ".country", ".gq", ".tk", ".cf",
];

fn deleet(label: &str) -> String {
    label
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '$' => 's',
            '@' => 'a',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, &ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur.push((prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Extract `host` and `had_userinfo` from a URL string.
fn host_of(url: &str) -> (String, bool) {
    let after = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
    let (had_userinfo, hostport) = match authority.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, authority),
    };
    let host = hostport.split(':').next().unwrap_or(hostport);
    (host.to_string(), had_userinfo)
}

/// Registrable label (second-level domain) of a host, best-effort.
fn main_label(host: &str) -> &str {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2]
    } else {
        host
    }
}

fn is_ipv4(host: &str) -> bool {
    let p: Vec<&str> = host.split('.').collect();
    p.len() == 4 && p.iter().all(|o| o.parse::<u8>().is_ok())
}

/// Scan `text` for suspicious URLs.
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for m in RE_URL.find_iter(text) {
        let url = m.as_str();
        let span = Some([m.start(), m.end()]);
        let (host, had_userinfo) = host_of(url);

        let add = |findings: &mut Vec<Finding>, type_: &str, risk: Risk, detail: &str| {
            findings.push(Finding::new("maliciousUrls", type_, risk, span, detail));
        };

        if had_userinfo {
            add(
                &mut findings,
                "userinfo_trick",
                Risk::High,
                "URL embeds user@host — the real destination is the part after '@'",
            );
        }
        if !host.is_ascii() {
            add(
                &mut findings,
                "idn_homograph",
                Risk::High,
                "non-ASCII host — possible unicode homograph attack",
            );
        } else if host.contains("xn--") {
            add(
                &mut findings,
                "punycode",
                Risk::Medium,
                "punycode host (xn--) — verify the decoded domain",
            );
        }
        if is_ipv4(&host) {
            add(
                &mut findings,
                "ip_url",
                Risk::Medium,
                "URL points to a raw IP address rather than a domain",
            );
        }
        if SUSPICIOUS_TLDS
            .iter()
            .any(|t| host.to_ascii_lowercase().ends_with(t))
        {
            add(
                &mut findings,
                "suspicious_tld",
                Risk::Medium,
                "suspicious top-level domain",
            );
        }
        // typosquatting of a known brand
        let label = main_label(&host).to_ascii_lowercase();
        let norm = deleet(&label);
        for brand in BRANDS {
            let is_squat = label != *brand && (norm == *brand || levenshtein(&label, brand) == 1);
            if is_squat {
                add(
                    &mut findings,
                    "typosquat",
                    Risk::High,
                    "domain closely resembles a well-known brand (possible typosquat)",
                );
                break;
            }
        }
    }
    findings
}
