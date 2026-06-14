import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    outExtension({ format }) {
      return { js: format === "esm" ? ".mjs" : ".cjs" };
    },
    dts: true,
    sourcemap: true,
    clean: true,
    external: ["../binding.js"],
  },
  {
    entry: { browser: "src/browser.ts" },
    format: ["esm"],
    outExtension() {
      return { js: ".mjs" };
    },
    dts: true,
    sourcemap: true,
    clean: false,
    external: ["../wasm/llm-io-guard.js"],
  },
]);
