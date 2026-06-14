//! Node.js binding for llm-io-guard. Thin wrapper over the core JSON facade.
//! Scanning is synchronous and offline; the TypeScript layer adds the `Guard`
//! orchestration and the opt-in network scanners.

use llm_io_guard_core as core;
use napi_derive::napi;

#[napi]
pub fn redact(text: String, entities: Vec<String>, mode: String) -> String {
    core::facade::redact_json(&text, &entities, &mode)
}

#[napi]
pub fn restore(text: String, vault_json: String) -> String {
    core::facade::restore_json(&text, &vault_json)
}

#[napi(js_name = "scanInjection")]
pub fn scan_injection(text: String, sensitivity: String) -> String {
    core::facade::scan_injection_json(&text, &sensitivity)
}

#[napi(js_name = "scanSecrets")]
pub fn scan_secrets(text: String) -> String {
    core::facade::scan_secrets_json(&text)
}

#[napi(js_name = "scanSecretLeak")]
pub fn scan_secret_leak(text: String) -> String {
    core::facade::scan_secret_leak_json(&text)
}

#[napi(js_name = "scanUrls")]
pub fn scan_urls(text: String) -> String {
    core::facade::scan_urls_json(&text)
}

#[napi(js_name = "extractPackages")]
pub fn extract_packages(text: String, ecosystems: Vec<String>) -> String {
    core::facade::extract_packages_json(&text, &ecosystems)
}

#[napi(js_name = "StreamScanner")]
pub struct JsStreamScanner {
    inner: core::StreamScanner,
}

#[napi]
impl JsStreamScanner {
    #[napi(constructor)]
    pub fn new(config_json: String) -> Self {
        JsStreamScanner {
            inner: core::StreamScanner::new(core::facade::parse_stream_config(&config_json)),
        }
    }

    #[napi]
    pub fn push(&mut self, chunk: String) -> String {
        core::facade::step_to_json(&self.inner.push(&chunk))
    }

    #[napi]
    pub fn finish(&mut self) -> String {
        core::facade::step_to_json(&self.inner.finish())
    }
}
