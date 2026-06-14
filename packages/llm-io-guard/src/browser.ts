/**
 * llm-io-guard (browser/edge entry, WASM). Call `init()` once before use.
 *
 * ```js
 * import { init, Guard, piiRedact } from "llm-io-guard/browser";
 * await init();
 * const guard = new Guard({ input: [piiRedact()] });
 * ```
 */
import initWasm, * as wasm from "../wasm/llm-io-guard.js";
import { makeGuard, type Native } from "./runtime.js";
import type { GuardConfig, ScanResult, Vault } from "./types.js";

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

let nativeRef: Native | null = null;

/** Load and initialize the WASM module. Call once before constructing a Guard. */
export async function init(
  source?: string | URL | Response | WebAssembly.Module | BufferSource,
): Promise<void> {
  await initWasm(source === undefined ? undefined : { module_or_path: source });
  nativeRef = wasm as unknown as Native;
}

/** Input/output safety guard (browser/edge, backed by WASM). Requires `init()`. */
export class Guard {
  private impl: InstanceType<ReturnType<typeof makeGuard>>;
  constructor(config: GuardConfig = {}) {
    if (!nativeRef) {
      throw new Error("llm-io-guard/browser: call await init() before new Guard()");
    }
    this.impl = new (makeGuard(nativeRef))(config);
  }
  scanInput(text: string): Promise<ScanResult> {
    return this.impl.scanInput(text);
  }
  scanOutput(text: string, opts?: { vault?: Vault }): Promise<ScanResult> {
    return this.impl.scanOutput(text, opts);
  }
  scanStream(
    stream: AsyncIterable<string>,
    opts?: { vault?: Vault },
  ): AsyncIterable<{ chunk: string; result: ScanResult }> {
    return this.impl.scanStream(stream, opts);
  }
}
