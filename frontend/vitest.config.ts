import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  // esbuild provides the automatic JSX runtime without a React plugin.
  esbuild: { jsx: "automatic" },
  test: {
    // Component and accessibility tests need a DOM by default.
    environment: "jsdom",
    // List DOM-free tests explicitly so new tests retain jsdom by default.
    environmentMatchGlobs: [
      ["src/hooks/async-state.test.ts", "node"],
      ["src/lib/content-disposition.test.ts", "node"],
      ["src/lib/fetch-retry.test.ts", "node"],
      ["src/lib/format/date.test.ts", "node"],
      ["src/lib/safe-href.test.ts", "node"],
      ["src/lib/severity.test.ts", "node"],
      ["src/lib/utils.test.ts", "node"],
      ["src/proxy.test.ts", "node"],
      ["src/std-lib/std-lib.test.ts", "node"],
    ],
    // Allow for jsdom worker contention without masking hangs for long.
    testTimeout: 15_000,
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
    globals: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
