import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  // No @vitejs/plugin-react: it wants vite 8 while this project is on vite 5
  // (via vitest 2.x), and it is not needed; esbuild compiles JSX directly
  // with the automatic runtime, which is all these tests require. One fewer
  // dependency and no peer-range conflict to carry.
  esbuild: { jsx: "automatic" },
  test: {
    // Component and accessibility assertions need a DOM, so jsdom is the
    // default. 53 of the 62 test files genuinely render something.
    //
    // The nine that do not are listed in environmentMatchGlobs below and
    // run in node. This revises an earlier note here which said jsdom was
    // "not slower by enough to matter at this suite size" -- measured, it
    // does: a full local run reported `environment 1317.51s` against
    // 415.84s of wall clock, the largest line in the breakdown by a wide
    // margin and roughly three workers' worth of continuous jsdom
    // construction.
    environment: "jsdom",
    // The handful of test files that touch no DOM at all, listed one by
    // one. Every other file gets jsdom.
    //
    // Enumerated rather than globbed, and that is the whole point. An
    // earlier version of this used ["src/lib/**/*.test.ts", "node"], which
    // was true of src/lib the day it was measured and then silently
    // captured the next file added there: src/lib/dashboard-preferences.ts
    // reads window.localStorage, and its test failed with "window is not
    // defined" the moment it landed on main. A glob opts future files OUT
    // of the DOM by default; a list opts them IN. Getting that direction
    // wrong turns an unrelated PR into a broken build, which is the exact
    // class of problem this config change exists to stop causing.
    //
    // Adding to this list is a deliberate act. If a file here later grows
    // a DOM dependency it fails immediately and legibly with "window is
    // not defined" -- a clear signal, not a flake.
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
    // Up from vitest's 5000ms default (#496). That default is what turned
    // environment contention into flaky failures: a test's timer runs while
    // its worker is still constructing jsdom environments for other files,
    // so an async assertion can lose a race that has nothing to do with the
    // code under test. Observed twice on the same commit, on two different
    // tests, one of which passed 3/3 in isolation.
    //
    // This raises the ceiling on a genuinely hung test too, which is the
    // cost. 15s is chosen to sit well clear of the observed contention
    // without hiding a real hang for long.
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
