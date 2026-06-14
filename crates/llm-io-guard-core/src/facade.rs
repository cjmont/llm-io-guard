//! JSON-string facade shared by the napi and wasm bindings, so parsing and
//! serialization live in one place and the bindings stay thin.

use serde::Deserialize;

use crate::pii::{self, Entity, Mode};
use crate::stream::{StreamConfig, StreamStep};
use crate::types::{Risk, Vault};
use crate::{injection, packages, secrets, urls};

fn parse_entity(s: &str) -> Option<Entity> {
    Some(match s.to_ascii_lowercase().as_str() {
        "email" => Entity::Email,
        "phone" => Entity::Phone,
        "card" | "credit_card" | "creditcard" => Entity::CreditCard,
        "iban" => Entity::Iban,
        "ip" => Entity::Ip,
        "ssn" | "us_ssn" => Entity::UsSsn,
        "dni" | "es_dni" | "nie" => Entity::EsDni,
        _ => return None,
    })
}

fn parse_entities(list: &[String]) -> Vec<Entity> {
    if list.is_empty() {
        return pii::DEFAULT_ENTITIES.to_vec();
    }
    list.iter().filter_map(|s| parse_entity(s)).collect()
}

fn parse_mode(s: &str) -> Mode {
    match s.to_ascii_lowercase().as_str() {
        "mask" => Mode::Mask,
        "hash" => Mode::Hash,
        _ => Mode::Replace,
    }
}

fn parse_sensitivity(s: &str) -> injection::Sensitivity {
    match s.to_ascii_lowercase().as_str() {
        "low" => injection::Sensitivity::Low,
        "high" => injection::Sensitivity::High,
        _ => injection::Sensitivity::Medium,
    }
}

fn parse_ecosystem(s: &str) -> Option<packages::Ecosystem> {
    Some(match s.to_ascii_lowercase().as_str() {
        "npm" => packages::Ecosystem::Npm,
        "pypi" => packages::Ecosystem::Pypi,
        "crates" => packages::Ecosystem::Crates,
        "pub" => packages::Ecosystem::Pub,
        "rubygems" => packages::Ecosystem::Rubygems,
        _ => return None,
    })
}

fn parse_risk(s: &str) -> Risk {
    match s.to_ascii_lowercase().as_str() {
        "none" => Risk::None,
        "low" => Risk::Low,
        "medium" => Risk::Medium,
        "high" => Risk::High,
        _ => Risk::Critical,
    }
}

pub fn redact_json(text: &str, entities: &[String], mode: &str) -> String {
    let r = pii::redact(text, &parse_entities(entities), parse_mode(mode));
    serde_json::to_string(&r).unwrap()
}

pub fn restore_json(text: &str, vault_json: &str) -> String {
    let vault: Vault = serde_json::from_str(vault_json).unwrap_or_default();
    pii::restore(text, &vault)
}

pub fn scan_injection_json(text: &str, sensitivity: &str) -> String {
    serde_json::to_string(&injection::scan(text, parse_sensitivity(sensitivity))).unwrap()
}

pub fn scan_secrets_json(text: &str) -> String {
    serde_json::to_string(&secrets::scan(text)).unwrap()
}

pub fn scan_secret_leak_json(text: &str) -> String {
    serde_json::to_string(&secrets::scan_leak(text)).unwrap()
}

pub fn scan_urls_json(text: &str) -> String {
    serde_json::to_string(&urls::scan(text)).unwrap()
}

pub fn extract_packages_json(text: &str, ecosystems: &[String]) -> String {
    let ecos: Vec<packages::Ecosystem> = if ecosystems.is_empty() {
        packages::DEFAULT_ECOSYSTEMS.to_vec()
    } else {
        ecosystems
            .iter()
            .filter_map(|s| parse_ecosystem(s))
            .collect()
    };
    serde_json::to_string(&packages::extract(text, &ecos)).unwrap()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StreamConfigJson {
    #[serde(default)]
    overlap: Option<usize>,
    #[serde(default)]
    cut_at: Option<String>,
    #[serde(default)]
    secret_leak: Option<bool>,
    #[serde(default)]
    malicious_urls: Option<bool>,
    #[serde(default)]
    pii_entities: Vec<String>,
    #[serde(default)]
    vault: Vault,
}

/// Build a [`StreamConfig`] from a JSON config object (all fields optional).
pub fn parse_stream_config(json: &str) -> StreamConfig {
    let c: StreamConfigJson = serde_json::from_str(json).unwrap_or(StreamConfigJson {
        overlap: None,
        cut_at: None,
        secret_leak: None,
        malicious_urls: None,
        pii_entities: Vec::new(),
        vault: Vault::new(),
    });
    let d = StreamConfig::default();
    StreamConfig {
        overlap: c.overlap.unwrap_or(d.overlap),
        cut_at: c.cut_at.as_deref().map(parse_risk).unwrap_or(d.cut_at),
        secret_leak: c.secret_leak.unwrap_or(d.secret_leak),
        malicious_urls: c.malicious_urls.unwrap_or(d.malicious_urls),
        pii_entities: c
            .pii_entities
            .iter()
            .filter_map(|s| parse_entity(s))
            .collect(),
        vault: c.vault,
    }
}

/// Serialize a [`StreamStep`] to JSON.
pub fn step_to_json(step: &StreamStep) -> String {
    serde_json::to_string(step).unwrap()
}
