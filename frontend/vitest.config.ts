import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  // No @vitejs/plugin-react: it wants vite 8 while this project is on vite 5
  // (via vitest 2.x), and it is not needed; esbuild compiles JSX directly
  // with the automatic runtime, which is all these tests require. One fewer
  // dependency and no peer-range conflict to carry.
  esbuild: { jsx: "automatic" },
  test: {
    // Component and accessibility assertions need a DOM. The existing pure
    // unit tests run fine here too; jsdom is slower than node, but not by
    // enough to matter at this suite size, and one environment beats
    // maintaining a project split.
    environment: "jsdom",
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
