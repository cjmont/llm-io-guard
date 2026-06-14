/**
 * llm-io-guard (Node entry) — offline, in-process I/O safety for LLM apps.
 * Defense-in-depth, not a guarantee. See "Limitations & threat model" in the README.
 */
import native from "../binding.js";
import { makeGuard, type Native } from "./runtime.js";

export * from "./types.js";
export {
  piiRedact,
  promptInjection,
  secrets,
  bannedTopics,
  piiRestore,
  secretLeak,
  maliciousUrls,
  packageHallucination,
  defaultRegistry,
} from "./runtime.js";

/** Input/output safety guard (Node, backed by the Rust core via napi). */
export const Guard = makeGuard(native as unknown as Native);
