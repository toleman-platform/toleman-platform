/**
 * Fails if any Server Component imports a value from a "use client" module
 * (issue #206).
 *
 * Runs the full ESLint config but reports on this one rule only. That is
 * deliberate: `npx eslint src` currently surfaces 24 pre-existing errors
 * unrelated to this work, so a blanket lint gate would either fail CI on day
 * one or have to be non-blocking; and a non-blocking gate does not prevent
 * anything. Scoping the gate to this rule makes it genuinely enforced now,
 * without holding it hostage to a cleanup it has nothing to do with.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ESLint } from "eslint";

const RULE_ID = "toleman/no-client-value-import-in-server";

const results = await new ESLint().lintFiles(["src"]);
const violations = results.flatMap((result) =>
  result.messages
    .filter((m) => m.ruleId === RULE_ID)
    .map((m) => ({ file: result.filePath, line: m.line, message: m.message })),
);

if (violations.length === 0) {
  console.log(`${RULE_ID}: clean`);
} else {
  console.error(`${RULE_ID}: ${violations.length} violation(s)\n`);
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}\n    ${v.message}\n`);
  }
}

/**
 * Second gate: the layer map in COMPONENTS.md. `components/ui/*` is L1/L2 and
 * `components/*` is L3, and a layer may only import downward. Nothing
 * enforced this, so a shared primitive could reach upward into a feature
 * module and eslint would stay green -- which is how the new PaginatedList
 * shell, the module every other list is meant to adopt, came to import from
 * a layer above it. One upward import in a shared primitive drags the whole
 * layer up with it, so it is worth failing the build over.
 */
const UI_DIR = "src/components/ui";
const UPWARD = /from\s+"@\/components\/(?!ui\/)[^"]+"/g;

function tsFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(full);
    return /\.tsx?$/.test(e.name) ? [full] : [];
  });
}

const upward = tsFiles(UI_DIR).flatMap((file) =>
  (readFileSync(file, "utf8").match(UPWARD) ?? []).map((hit) => ({ file, hit })),
);

if (upward.length > 0) {
  console.error(`components/ui upward imports: ${upward.length} violation(s)\n`);
  for (const v of upward) {
    console.error(`  ${v.file}\n    ${v.hit}\n`);
  }
  console.error("  components/ui is L1/L2; it may not import from components/ (L3).");
  console.error("  Move the shared module down into components/ui, or invert the dependency.\n");
  process.exit(1);
}

console.log("components/ui upward imports: clean");

if (violations.length > 0) process.exit(1);
