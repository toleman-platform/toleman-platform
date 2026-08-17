import path from "node:path";
import { RuleTester } from "eslint";
import tsParser from "@typescript-eslint/parser";
import rule from "./no-client-value-import-in-server.mjs";

// Fixtures live on disk because the rule resolves the imported module and
// reads its directive -- that file I/O is the part worth testing.
const FIXTURES = path.join(import.meta.dirname, "__fixtures__");
const options = [{ srcRoot: FIXTURES }];
const serverFile = path.join(FIXTURES, "server-consumer.tsx");
const clientFile = path.join(FIXTURES, "client-consumer.tsx");

const ruleTester = new RuleTester({
  languageOptions: {
    parser: tsParser,
    ecmaVersion: 2022,
    sourceType: "module",
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

ruleTester.run("no-client-value-import-in-server", rule, {
  valid: [
    {
      name: "server component rendering a client component",
      filename: serverFile,
      options,
      code: `import { ThemeToggle } from "./client-module";
             export default function Page() { return <ThemeToggle />; }`,
    },
    {
      name: "server component importing a type from a client module",
      filename: serverFile,
      options,
      code: `import type { Theme } from "./client-module";
             export default function Page(t: Theme) { return null; }`,
    },
    {
      name: "server component importing values from a plain module (the fix)",
      filename: serverFile,
      options,
      code: `import { THEME_COOKIE_KEY, pageSizeFromParams } from "./plain-module";
             export default function Page() { return pageSizeFromParams(THEME_COOKIE_KEY); }`,
    },
    {
      name: "client-to-client import is fine",
      filename: clientFile,
      options,
      code: `"use client";
             import { THEME_COOKIE_KEY } from "./client-module";
             export const k = THEME_COOKIE_KEY;`,
    },
    {
      name: "bare package imports are not policed",
      filename: serverFile,
      options,
      code: `import { useMemo } from "react"; export default function P() { return useMemo; }`,
    },
  ],

  invalid: [
    {
      // The #196 shape: a constant. This one fails SILENTLY at runtime.
      name: "server component importing a constant from a client module",
      filename: serverFile,
      options,
      code: `import { THEME_COOKIE_KEY } from "./client-module";
             export default function Page() { return THEME_COOKIE_KEY; }`,
      errors: [{ messageId: "clientValueInServer" }],
    },
    {
      // The #204 shape: a function. This one throws at request time.
      name: "server component calling a function from a client module",
      filename: serverFile,
      options,
      code: `import { pageSizeFromParams } from "./client-module";
             export default function Page() { return pageSizeFromParams("50"); }`,
      errors: [{ messageId: "clientValueInServer" }],
    },
    {
      name: "component import is allowed but a value alongside it is not",
      filename: serverFile,
      options,
      code: `import { ThemeToggle, THEME_COOKIE_KEY } from "./client-module";
             export default function Page() { return <ThemeToggle data-k={THEME_COOKIE_KEY} />; }`,
      errors: [{ messageId: "clientValueInServer" }],
    },
  ],
});

console.log("no-client-value-import-in-server: all cases pass");
