# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-14

### Added

- **Input scanners:** `piiRedact` (reversible, vault-based; structured PII with
  Luhn/IBAN/DNI validation; replace/mask/hash modes), `promptInjection`
  (low/medium/high heuristics), `secrets`, `bannedTopics`.
- **Output scanners:** `piiRestore`, `secretLeak`, `maliciousUrls` (typosquat /
  IDN homograph / punycode / IP-URL / userinfo trick), `packageHallucination`
  (offline name extraction + opt-in registry lookup with graceful degradation).
- **Streaming:** `scanStream` with a 1 KiB overlap window — cross-chunk detection,
  on-the-fly PII restore, and cut on critical findings.
- Rich `ScanResult` (`allowed`, `risk`, `findings`, `sanitized`, `vault`); only
  policy decides blocking. Configurable `onViolation`: block / warn / sanitize.
- Rust core compiled to **Node (napi-rs)** and **edge/browser (WASM)**; dual
  ESM + CJS with generated TypeScript declarations.
- CI (Rust + Node×WASM matrix), release pipeline (multi-platform prebuilds, npm
  provenance, cosign-signed binaries), and a GitHub Pages docs site.

### Notes

- The WASM bundle is ~913 KB (uncompressed); size optimization (wasm-opt /
  regex-lite) is planned for a follow-up release.

[0.1.0]: https://github.com/cjmont/llm-io-guard/releases/tag/v0.1.0
