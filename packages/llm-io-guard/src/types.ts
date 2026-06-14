/** Public type surface of llm-io-guard (single source of truth). */

export type Risk = "none" | "low" | "medium" | "high" | "critical";
export type Action = "block" | "warn" | "sanitize";

export interface Finding {
  scanner: string;
  type: string;
  risk: Risk;
  span?: [number, number];
  detail: string;
}

/** Maps a placeholder (e.g. `[PII_EMAIL_1]`) to the original value. In-memory only. */
export type Vault = Record<string, string>;

export interface ScanResult {
  allowed: boolean;
  risk: Risk;
  findings: Finding[];
  /** Text with PII/secrets redacted (when a scanner produced one), else null. */
  sanitized: string | null;
  /** Placeholder→value map, to restore later in the output. */
  vault?: Vault;
}

/** Looks up whether a package exists in its registry. Override for custom infra. */
export type RegistryFetcher = (
  ecosystem: string,
  name: string,
) => Promise<boolean | null>; // true=exists, false=missing, null=unknown (network)

/** Optional NER hook for free-form PII (names/addresses) the rule core can't do. */
export type NerHook = (
  text: string,
) => Promise<Finding[]> | Finding[];

export type ScannerSpec =
  | { kind: "piiRedact"; entities: string[]; mode: "replace" | "mask" | "hash"; nerHook?: NerHook }
  | { kind: "promptInjection"; sensitivity: "low" | "medium" | "high" }
  | { kind: "secrets" }
  | { kind: "bannedTopics"; denylist: string[] }
  | { kind: "piiRestore" }
  | { kind: "secretLeak" }
  | { kind: "maliciousUrls" }
  | {
      kind: "packageHallucination";
      ecosystems: string[];
      failClosed: boolean;
      registry?: RegistryFetcher;
    };

export interface GuardConfig {
  input?: ScannerSpec[];
  output?: ScannerSpec[];
  onViolation?: Action; // default 'block'
}
