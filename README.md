# llm-io-guard

🇬🇧 **Offline, in-process input/output safety layer for LLM apps** (Rust core →
Node via napi + edge/browser via WASM). Redacts PII reversibly, flags prompt
injection, secrets, malicious URLs and hallucinated packages. Defense-in-depth,
not a guarantee.

🇪🇸 **Capa de seguridad offline e in-process de entrada/salida para apps con LLM**
(core en Rust → Node vía napi + edge/navegador vía WASM). Redacta PII de forma
reversible y detecta prompt injection, secretos, URLs maliciosas y paquetes
alucinados. Defensa en capas, no una garantía.

📦 Full docs & bilingual README: [`packages/llm-io-guard`](packages/llm-io-guard/README.md) ·
🌐 Examples site: [`docs/`](docs/) (GitHub Pages)

## Repository layout / Estructura

```
llm-io-guard/
├─ crates/
│  ├─ llm-io-guard-core/   # all offline scanners + vault + streaming (Rust, tested)
│  ├─ llm-io-guard-napi/   # Node binding (napi-rs)
│  └─ llm-io-guard-wasm/   # edge/browser binding (wasm-bindgen)
├─ packages/llm-io-guard/  # npm package (TypeScript, dual ESM/CJS, Node + browser)
├─ examples/               # node-openai, streaming, edge-worker
├─ docs/                   # GitHub Pages (bilingual examples)
└─ .github/workflows/      # ci.yml, release.yml, pages.yml
```

## Develop / Desarrollo

```bash
cargo test -p llm-io-guard-core          # core scanners + adversarial corpus
cd packages/llm-io-guard
npm ci && npm run build && npm test      # napi + wasm + TypeScript + Node tests
```

## Security / Seguridad

Defense-in-depth with documented limitations — see the
[Limitations & threat model](packages/llm-io-guard/README.md#-limitations--threat-model--limitaciones-y-modelo-de-amenaza)
section and [SECURITY.md](SECURITY.md) (finding taxonomy + reporting).

## License

[Apache-2.0](LICENSE)
