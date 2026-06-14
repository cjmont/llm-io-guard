# llm-io-guard

> 🛡️ **Offline, in-process safety layer for LLM apps** — scans what goes **into**
> and comes **out of** a language model: redacts PII (reversibly), flags prompt
> injection, secrets, malicious URLs and hallucinated packages. Rust core,
> runs in **Node** and on the **edge/browser** (WASM). No network, no sidecar.
>
> 🛡️ **Capa de seguridad offline e in-process para apps con LLM** — escanea lo que
> **entra** y **sale** del modelo: redacta PII (de forma reversible), detecta
> prompt injection, secretos, URLs maliciosas y paquetes alucinados. Core en Rust,
> corre en **Node** y en el **edge/navegador** (WASM). Sin red, sin sidecar.

> ⚠️ **Defense-in-depth, not a guarantee / Defensa en capas, no una garantía.**
> Heuristic detection has false negatives. This **complements** good practices
> (least privilege, separating instructions from data); it does not replace them.
> See [Limitations & threat model](#-limitations--threat-model--limitaciones-y-modelo-de-amenaza).

---

## 📦 Install / Instalación

```bash
npm install llm-io-guard
```

Prebuilt native binaries for Linux/macOS/Windows — **`npm install` compiles nothing**.
A WebAssembly build is included for the edge/browser.

_Binarios nativos precompilados para Linux/macOS/Windows — **`npm install` no compila nada**.
Incluye build WebAssembly para edge/navegador._

---

# 🇬🇧 English

### The idea in 30 seconds

You have an app that sends user text to an LLM (OpenAI, Anthropic, a local model…).
Two problems: (1) the user's text may contain **PII or secrets** you must not send
to a third party, and (2) the model's reply may contain **leaked secrets, bad URLs,
or made-up package names**. `llm-io-guard` sits on both sides:

1. **Before** the call: redact PII into stable placeholders and get a `vault`.
2. Send the **redacted** text to the model.
3. **After** the call: restore the real PII from the `vault`, and scan the reply.

The redaction is **reversible** — the model never sees the real data, but your user
still gets a useful answer with the real values put back.

### Quickstart (wrap one LLM call)

```js
import { Guard, piiRedact, promptInjection, secrets, piiRestore, secretLeak } from "llm-io-guard";

const guard = new Guard({
  input: [piiRedact(), promptInjection(), secrets()], // runs on the user's text
  output: [piiRestore(), secretLeak()],               // runs on the model's reply
  onViolation: "block",                               // 'block' | 'warn' | 'sanitize'
});

// 1) Scan the user input. `sanitized` has no PII; keep the `vault` for later.
const inp = await guard.scanInput(userText);
if (!inp.allowed) throw new Error("unsafe input: " + inp.findings.map(f => f.type));

// 2) Call your LLM with the SANITIZED text (no PII leaves your process).
const reply = await callYourLLM(inp.sanitized);

// 3) Scan the output and restore the real PII via the vault.
const out = await guard.scanOutput(reply, { vault: inp.vault });
console.log(out.sanitized); // the reply, with real PII put back
```

Every call returns a **rich result**, never a bare boolean:

```ts
interface ScanResult {
  allowed: boolean;          // false if policy 'block' and risk is high/critical
  risk: "none" | "low" | "medium" | "high" | "critical";
  findings: Finding[];       // { scanner, type, risk, span?, detail }
  sanitized: string | null;  // transformed text (redacted / restored), if changed
  vault?: Record<string,string>; // placeholder → original value (in-memory only)
}
```

### Scanners

| Scanner | Side | What it does |
| --- | --- | --- |
| `piiRedact({ entities, mode })` | input | Reversibly redacts structured PII (email, phone, card+Luhn, IBAN+mod97, IP, US-SSN, ES-DNI). `mode`: `replace` (vault), `mask`, `hash`. Free-form names need the optional `nerHook`. |
| `promptInjection({ sensitivity })` | input | Heuristics for instruction-override, jailbreak, fake delimiters, obfuscation. `sensitivity`: `low`/`medium`/`high` (default `medium`). |
| `secrets()` | input | API keys (OpenAI/AWS/GitHub/Google/Slack/Stripe), JWTs, private keys. |
| `bannedTopics({ denylist })` | input | Flags your custom denylisted terms. |
| `piiRestore()` | output | Restores real PII from the `vault` into the reply. |
| `secretLeak()` | output | Catches the model regurgitating credentials. |
| `maliciousUrls()` | output | Typosquatting, IDN homographs, punycode, IP-URLs, `user@host` tricks. |
| `packageHallucination({ ecosystems })` | output | Flags package names that don't exist in npm/pypi/crates/pub/rubygems. **Opt-in network**; degrades gracefully if the registry is unreachable. |

### Streaming

Scan the model's reply as it streams, token by token:

```js
for await (const { chunk, result } of guard.scanStream(modelStream, { vault: inp.vault })) {
  if (!result.allowed) break;  // cut the stream on a critical finding
  process.stdout.write(chunk); // PII already restored on the fly
}
```

An overlapping window (1 KiB by default) detects patterns that cross chunk
boundaries (a secret split across two tokens) and never emits a critical secret.

### Edge / browser (WASM)

```js
import { init, Guard, piiRedact } from "llm-io-guard/browser";
await init();                       // load the WASM module once
const guard = new Guard({ input: [piiRedact()] });
```

Works in Cloudflare Workers, Vercel Edge and the browser.

---

# 🇪🇸 Español

### La idea en 30 segundos

Tienes una app que manda texto del usuario a un LLM (OpenAI, Anthropic, un modelo
local…). Dos problemas: (1) el texto puede traer **PII o secretos** que no debes
enviar a un tercero, y (2) la respuesta del modelo puede traer **secretos filtrados,
URLs maliciosas o nombres de paquetes inventados**. `llm-io-guard` se pone en ambos lados:

1. **Antes** de la llamada: redacta la PII a placeholders estables y te da un `vault`.
2. Manda al modelo el texto **redactado**.
3. **Después**: restaura la PII real desde el `vault` y escanea la respuesta.

La redacción es **reversible**: el modelo nunca ve los datos reales, pero tu usuario
recibe una respuesta útil con los valores reales reinsertados.

### Quickstart (envuelve una llamada al LLM)

```js
import { Guard, piiRedact, promptInjection, secrets, piiRestore, secretLeak } from "llm-io-guard";

const guard = new Guard({
  input: [piiRedact(), promptInjection(), secrets()], // corre sobre el texto del usuario
  output: [piiRestore(), secretLeak()],               // corre sobre la respuesta del modelo
  onViolation: "block",                               // 'block' | 'warn' | 'sanitize'
});

// 1) Escanea la entrada. `sanitized` no tiene PII; guarda el `vault` para después.
const inp = await guard.scanInput(textoDelUsuario);
if (!inp.allowed) throw new Error("entrada insegura: " + inp.findings.map(f => f.type));

// 2) Llama a tu LLM con el texto SANITIZADO (la PII no sale de tu proceso).
const respuesta = await llamaATuLLM(inp.sanitized);

// 3) Escanea la salida y restaura la PII real con el vault.
const out = await guard.scanOutput(respuesta, { vault: inp.vault });
console.log(out.sanitized); // la respuesta, con la PII real reinsertada
```

### Escáneres

| Escáner | Lado | Qué hace |
| --- | --- | --- |
| `piiRedact({ entities, mode })` | input | Redacta PII estructurada de forma reversible (email, teléfono, tarjeta+Luhn, IBAN+mod97, IP, US-SSN, ES-DNI). `mode`: `replace` (vault), `mask`, `hash`. Nombres libres requieren el `nerHook` opcional. |
| `promptInjection({ sensitivity })` | input | Heurísticas de override de instrucciones, jailbreak, delimitadores falsos, ofuscación. `sensitivity`: `low`/`medium`/`high` (default `medium`). |
| `secrets()` | input | API keys (OpenAI/AWS/GitHub/Google/Slack/Stripe), JWTs, claves privadas. |
| `bannedTopics({ denylist })` | input | Marca términos de tu lista negra. |
| `piiRestore()` | output | Restaura la PII real desde el `vault`. |
| `secretLeak()` | output | Detecta al modelo regurgitando credenciales. |
| `maliciousUrls()` | output | Typosquatting, homoglyphs IDN, punycode, URLs a IP, truco `user@host`. |
| `packageHallucination({ ecosystems })` | output | Marca paquetes que no existen en npm/pypi/crates/pub/rubygems. **Red opt-in**; degrada con gracia si el registro no responde. |

### Streaming y edge

`guard.scanStream(stream, { vault })` escanea la respuesta token a token (ventana
solapada de 1 KiB para patrones que cruzan chunks; corta ante algo crítico). Para
edge/navegador usa `import { init, Guard } from "llm-io-guard/browser"` y llama a
`await init()` una vez.

---

## 🔎 Limitations & threat model / Limitaciones y modelo de amenaza

**🇬🇧** This library is **defense-in-depth**, not a guarantee.

- **Heuristic detection has false negatives.** It reduces the attack surface; it
  does not "block all prompt injection" or "guarantee zero PII leakage".
- **Prompt injection is an open problem** — no tool solves it. Treat these signals
  as one layer among many.
- **It complements, not replaces,** good practices: least privilege, separating
  instructions from untrusted data, human review for high-stakes actions.
- **Scanner caveats:** rule-based PII covers *structured* PII only — names/addresses
  need the optional `nerHook` (a model you provide). `packageHallucination` needs
  **network** and degrades gracefully (declares `unverifiable_package` when the
  registry is unreachable). Errors never log the sensitive content being scanned.

**🇪🇸** Esta librería es **defensa en capas**, no una garantía.

- **La detección heurística tiene falsos negativos.** Reduce la superficie de ataque;
  no "bloquea todo prompt injection" ni "garantiza cero fuga de PII".
- **El prompt injection es un problema abierto** — nadie lo resuelve. Trata estas
  señales como una capa más.
- **Complementa, no reemplaza,** las buenas prácticas: mínimo privilegio, separar
  instrucciones de datos no confiables, revisión humana en acciones críticas.
- **Matices por escáner:** la PII por reglas cubre solo PII *estructurada* —
  nombres/direcciones requieren el `nerHook` opcional (un modelo que tú provees).
  `packageHallucination` usa **red** y degrada con gracia (declara
  `unverifiable_package` si el registro no responde). Los errores nunca loguean el
  contenido sensible que escanean.

See [SECURITY.md](https://github.com/cjmont/llm-io-guard/blob/main/SECURITY.md) for
the full finding taxonomy and reporting policy.

## License

[Apache-2.0](https://github.com/cjmont/llm-io-guard/blob/main/LICENSE)
