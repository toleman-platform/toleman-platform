import path from "node:path";
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import noClientValueImportInServer from "./eslint-rules/no-client-value-import-in-server.mjs";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Issue #206. Next ships no rule for this; `no-async-client-component` is
  // a different thing. Twice now a Server Component has imported a value out
  // of a "use client" module -- once silently (#196), once loudly (#204).
  {
    plugins: { toleman: { rules: { "no-client-value-import-in-server": noClientValueImportInServer } } },
    rules: {
      "toleman/no-client-value-import-in-server": [
        "error",
        { srcRoot: path.join(import.meta.dirname, "src") },
      ],
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Deliberately contain the violation the rule catches, so they must not
    // fail the normal lint run. They are exercised by the rule's own test
    // (eslint-rules/*.test.mjs, run via `npm run test:lint-rules`).
    "eslint-rules/__fixtures__/**",
  ]),
]);

export default eslintConfig;
