/** Shared runtime: scanner factories, the Guard orchestrator, the default
 *  registry lookup, all parameterized over a `Native` binding (napi or wasm). */

import type {
  Action,
  Finding,
  GuardConfig,
  NerHook,
  RegistryFetcher,
  Risk,
  ScanResult,
  ScannerSpec,
  Vault,
} from "./types.js";

/** Low-level binding surface implemented by both napi and wasm. */
export interface Native {
  redact(text: string, entities: string[], mode: string): string;
  restore(text: string, vaultJson: string): string;
  scanInjection(text: string, sensitivity: string): string;
  scanSecrets(text: string): string;
  scanSecretLeak(text: string): string;
  scanUrls(text: string): string;
  extractPackages(text: string, ecosystems: string[]): string;
  StreamScanner: new (configJson: string) => {
    push(chunk: string): string;
    finish(): string;
  };
}

const RISK_ORDER: Record<Risk, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxRisk(findings: Finding[]): Risk {
  let r: Risk = "none";
  for (const f of findings) if (RISK_ORDER[f.risk] > RISK_ORDER[r]) r = f.risk;
  return r;
}

// ---- scanner factory functions (pure descriptors) ----

export function piiRedact(opts?: {
  entities?: string[];
  mode?: "replace" | "mask" | "hash";
  nerHook?: NerHook;
}): ScannerSpec {
  return {
    kind: "piiRedact",
    entities: opts?.entities ?? [],
    mode: opts?.mode ?? "replace",
    nerHook: opts?.nerHook,
  };
}
export function promptInjection(opts?: {
  sensitivity?: "low" | "medium" | "high";
}): ScannerSpec {
  return { kind: "promptInjection", sensitivity: opts?.sensitivity ?? "medium" };
}
export function secrets(): ScannerSpec {
  return { kind: "secrets" };
}
export function bannedTopics(opts: { denylist: string[] }): ScannerSpec {
  return { kind: "bannedTopics", denylist: opts.denylist };
}
export function piiRestore(): ScannerSpec {
  return { kind: "piiRestore" };
}
export function secretLeak(): ScannerSpec {
  return { kind: "secretLeak" };
}
export function maliciousUrls(): ScannerSpec {
  return { kind: "maliciousUrls" };
}
export function packageHallucination(opts?: {
  ecosystems?: string[];
  failClosed?: boolean;
  registry?: RegistryFetcher;
}): ScannerSpec {
  return {
    kind: "packageHallucination",
    ecosystems: opts?.ecosystems ?? ["npm", "pypi", "crates", "pub", "rubygems"],
    failClosed: opts?.failClosed ?? false,
    registry: opts?.registry,
  };
}

// ---- default registry lookup (the only network-touching part, opt-in) ----

const REGISTRY_URL: Record<string, (n: string) => string> = {
  npm: (n) => `https://registry.npmjs.org/${encodeURIComponent(n).replace("%40", "@")}`,
  pypi: (n) => `https://pypi.org/pypi/${encodeURIComponent(n)}/json`,
  crates: (n) => `https://crates.io/api/v1/crates/${encodeURIComponent(n)}`,
  pub: (n) => `https://pub.dev/api/packages/${encodeURIComponent(n)}`,
  rubygems: (n) => `https://rubygems.org/api/v1/gems/${encodeURIComponent(n)}.json`,
};

const registryCache = new Map<string, boolean | null>();

export const defaultRegistry: RegistryFetcher = async (ecosystem, name) => {
  const key = `${ecosystem}:${name}`;
  if (registryCache.has(key)) return registryCache.get(key) ?? null;
  const build = REGISTRY_URL[ecosystem];
  if (!build) return null;
  try {
    const res = await fetch(build(name), {
      headers: { "user-agent": "llm-io-guard" },
    });
    const ok = res.status === 200 ? true : res.status === 404 ? false : null;
    registryCache.set(key, ok);
    return ok;
  } catch {
    return null; // network failure → unknown, caller degrades
  }
};

// ---- Guard ----

export function makeGuard(native: Native) {
  function decide(findings: Finding[], action: Action): { allowed: boolean; risk: Risk } {
    const risk = maxRisk(findings);
    const blockedByPolicy =
      action === "block" && (risk === "high" || risk === "critical");
    return { allowed: !blockedByPolicy, risk };
  }

  async function runInput(spec: ScannerSpec, text: string, vault: Vault): Promise<{ text: string; findings: Finding[] }> {
    const findings: Finding[] = [];
    let out = text;
    switch (spec.kind) {
      case "piiRedact": {
        const r = JSON.parse(native.redact(out, spec.entities, spec.mode)) as {
          sanitized: string;
          vault: Vault;
          findings: Finding[];
        };
        findings.push(...r.findings);
        if (spec.mode === "replace") Object.assign(vault, r.vault);
        out = r.sanitized;
        if (spec.nerHook) findings.push(...(await spec.nerHook(out)));
        break;
      }
      case "promptInjection":
        findings.push(...(JSON.parse(native.scanInjection(out, spec.sensitivity)) as Finding[]));
        break;
      case "secrets":
        findings.push(...(JSON.parse(native.scanSecrets(out)) as Finding[]));
        break;
      case "bannedTopics": {
        const lower = out.toLowerCase();
        for (const term of spec.denylist) {
          let i = lower.indexOf(term.toLowerCase());
          while (i !== -1) {
            findings.push({
              scanner: "bannedTopics",
              type: "banned_topic",
              risk: "high",
              span: [i, i + term.length],
              detail: `banned topic: ${term}`,
            });
            i = lower.indexOf(term.toLowerCase(), i + 1);
          }
        }
        break;
      }
      default:
        break;
    }
    return { text: out, findings };
  }

  async function runOutput(spec: ScannerSpec, text: string, vault: Vault): Promise<{ text: string; findings: Finding[] }> {
    const findings: Finding[] = [];
    let out = text;
    switch (spec.kind) {
      case "piiRestore":
        out = native.restore(out, JSON.stringify(vault));
        break;
      case "secretLeak":
        findings.push(...(JSON.parse(native.scanSecretLeak(out)) as Finding[]));
        break;
      case "maliciousUrls":
        findings.push(...(JSON.parse(native.scanUrls(out)) as Finding[]));
        break;
      case "packageHallucination": {
        const cands = JSON.parse(native.extractPackages(out, spec.ecosystems)) as {
          ecosystem: string;
          name: string;
          span: [number, number];
        }[];
        const lookup = spec.registry ?? defaultRegistry;
        const checks = await Promise.all(
          cands.map(async (c) => ({ c, exists: await lookup(c.ecosystem, c.name) })),
        );
        for (const { c, exists } of checks) {
          if (exists === false) {
            findings.push({
              scanner: "packageHallucination",
              type: "hallucinated_package",
              risk: "high",
              span: c.span,
              detail: `package "${c.name}" not found in ${c.ecosystem} — possible hallucination/supply-chain risk`,
            });
          } else if (exists === null) {
            findings.push({
              scanner: "packageHallucination",
              type: "unverifiable_package",
              risk: spec.failClosed ? "high" : "low",
              span: c.span,
              detail: `could not verify "${c.name}" against ${c.ecosystem} (registry unreachable; degraded)`,
            });
          }
        }
        break;
      }
      default:
        break;
    }
    return { text: out, findings };
  }

  return class Guard {
    #input: ScannerSpec[];
    #output: ScannerSpec[];
    #onViolation: Action;

    constructor(config: GuardConfig = {}) {
      this.#input = config.input ?? [];
      this.#output = config.output ?? [];
      this.#onViolation = config.onViolation ?? "block";
    }

    async scanInput(text: string): Promise<ScanResult> {
      const vault: Vault = {};
      const findings: Finding[] = [];
      let current = text;
      let changed = false;
      for (const spec of this.#input) {
        const r = await runInput(spec, current, vault);
        if (r.text !== current) changed = true;
        current = r.text;
        findings.push(...r.findings);
      }
      const { allowed, risk } = decide(findings, this.#onViolation);
      return {
        allowed,
        risk,
        findings,
        sanitized: changed ? current : null,
        vault: Object.keys(vault).length ? vault : undefined,
      };
    }

    async scanOutput(text: string, opts?: { vault?: Vault }): Promise<ScanResult> {
      const vault = opts?.vault ?? {};
      const findings: Finding[] = [];
      let current = text;
      let changed = false;
      for (const spec of this.#output) {
        const r = await runOutput(spec, current, vault);
        if (r.text !== current) changed = true;
        current = r.text;
        findings.push(...r.findings);
      }
      const { allowed, risk } = decide(findings, this.#onViolation);
      return {
        allowed,
        risk,
        findings,
        sanitized: changed ? current : null,
      };
    }

    async *scanStream(
      stream: AsyncIterable<string>,
      opts?: { vault?: Vault },
    ): AsyncIterable<{ chunk: string; result: ScanResult }> {
      const cfg = {
        cutAt: this.#onViolation === "block" ? "high" : "critical",
        secretLeak: this.#output.some((s) => s.kind === "secretLeak"),
        maliciousUrls: this.#output.some((s) => s.kind === "maliciousUrls"),
        piiEntities: [] as string[],
        vault: opts?.vault ?? {},
      };
      const scanner = new native.StreamScanner(JSON.stringify(cfg));
      const toResult = (step: { output: string; findings: Finding[]; cut: boolean }): ScanResult => ({
        allowed: !step.cut,
        risk: maxRisk(step.findings),
        findings: step.findings,
        sanitized: step.output,
      });
      for await (const chunk of stream) {
        const step = JSON.parse(scanner.push(chunk));
        yield { chunk: step.output, result: toResult(step) };
        if (step.cut) return;
      }
      const last = JSON.parse(scanner.finish());
      yield { chunk: last.output, result: toResult(last) };
    }
  };
}
