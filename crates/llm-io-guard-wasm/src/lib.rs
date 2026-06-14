//! Browser/edge (WASM) binding for llm-io-guard. Thin wrapper over the core
//! JSON facade.

use llm_io_guard_core as core;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn redact(text: &str, entities: Vec<String>, mode: &str) -> String {
    core::facade::redact_json(text, &entities, mode)
}

#[wasm_bindgen]
pub fn restore(text: &str, vault_json: &str) -> String {
    core::facade::restore_json(text, vault_json)
}

#[wasm_bindgen(js_name = scanInjection)]
pub fn scan_injection(text: &str, sensitivity: &str) -> String {
    core::facade::scan_injection_json(text, sensitivity)
}

#[wasm_bindgen(js_name = scanSecrets)]
pub fn scan_secrets(text: &str) -> String {
    core::facade::scan_secrets_json(text)
}

#[wasm_bindgen(js_name = scanSecretLeak)]
pub fn scan_secret_leak(text: &str) -> String {
    core::facade::scan_secret_leak_json(text)
}

#[wasm_bindgen(js_name = scanUrls)]
pub fn scan_urls(text: &str) -> String {
    core::facade::scan_urls_json(text)
}

#[wasm_bindgen(js_name = extractPackages)]
pub fn extract_packages(text: &str, ecosystems: Vec<String>) -> String {
    core::facade::extract_packages_json(text, &ecosystems)
}

#[wasm_bindgen]
pub struct StreamScanner {
    inner: core::StreamScanner,
}

#[wasm_bindgen]
impl StreamScanner {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> StreamScanner {
        StreamScanner {
            inner: core::StreamScanner::new(core::facade::parse_stream_config(config_json)),
        }
    }

    pub fn push(&mut self, chunk: &str) -> String {
        core::facade::step_to_json(&self.inner.push(chunk))
    }

    pub fn finish(&mut self) -> String {
        core::facade::step_to_json(&self.inner.finish())
    }
}
