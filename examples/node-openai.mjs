// Example: wrap an LLM call with reversible PII redaction (Node).
//
// Real import: import { Guard, piiRedact, ... } from "llm-io-guard";
// Here we use the locally-built package so the example runs from the repo.
import {
  Guard,
  piiRedact,
  promptInjection,
  secrets,
  piiRestore,
  secretLeak,
} from "../packages/llm-io-guard/dist/index.mjs";

// Pretend LLM: echoes back, referencing whatever placeholder it received.
async function callYourLLM(prompt) {
  const ph = prompt.match(/\[PII_[A-Z]+_\d+\]/)?.[0] ?? "the user";
  return `Thanks! I've noted your details and will email ${ph} shortly.`;
}

const guard = new Guard({
  input: [piiRedact(), promptInjection(), secrets()],
  output: [piiRestore(), secretLeak()],
  onViolation: "block",
});

const userText = "Hi, my email is ada@example.com — please confirm my order.";

// 1) Scan input. PII becomes placeholders; keep the vault.
const inp = await guard.scanInput(userText);
console.log("sanitized input :", inp.sanitized); // no real email
console.log("vault           :", inp.vault);
if (!inp.allowed) {
  console.error("blocked:", inp.findings.map((f) => f.type));
  process.exit(1);
}

// 2) Call the model with the sanitized text (no PII leaves the process).
const reply = await callYourLLM(inp.sanitized);

// 3) Scan output and restore the real PII via the vault.
const out = await guard.scanOutput(reply, { vault: inp.vault });
console.log("final output    :", out.sanitized); // real email restored
console.log("output findings :", out.findings.map((f) => f.type));
