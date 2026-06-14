# Security Policy

## Defense-in-depth, not a guarantee

`llm-io-guard` reduces the attack surface of LLM input/output. It does **not**
"block all prompt injection" or "guarantee zero PII leakage". Heuristic detection
has false negatives. It complements — never replaces — least privilege, separating
instructions from untrusted data, and human review for high-stakes actions.

## Finding taxonomy

Each `Finding` has `{ scanner, type, risk, span?, detail }`. Overall `risk` is the
max severity of the findings.

| scanner | example types | typical risk |
| --- | --- | --- |
| `piiRedact` | EMAIL, PHONE, CARD, IBAN, IP, SSN, DNI | medium–high |
| `promptInjection` | instruction_override, jailbreak, fake_delimiter, obfuscation, encoding_obfuscation, prompt_leak, role_manipulation | medium–high |
| `secrets` | openai_api_key, aws_access_key_id, github_token, google_api_key, slack_token, stripe_key, private_key, jwt | high–critical |
| `bannedTopics` | banned_topic | high |
| `secretLeak` | (same secret types, on output) | high–critical |
| `maliciousUrls` | typosquat, idn_homograph, punycode, ip_url, suspicious_tld, userinfo_trick | medium–high |
| `packageHallucination` | hallucinated_package, unverifiable_package | high / low (degraded) |

Network- or model-dependent scanners degrade gracefully and declare it in their
findings (e.g. `unverifiable_package` when a registry is unreachable). The rule
core covers only **structured** PII; names/addresses need the optional `nerHook`.

## Privacy

Core scanners are **offline and in-process**: no network calls, and prompt content
never leaves the process. Only `packageHallucination` (opt-in) and a user-provided
`nerHook` may touch the network/a model. The PII `vault` lives in process memory and
is never persisted by this library. Errors never log the sensitive content scanned.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting (the
repository's **Security** tab → "Report a vulnerability"), or contact the maintainer
(**carlosmontanor** on npm). Expect acknowledgement within 72 hours and coordinated
disclosure.
