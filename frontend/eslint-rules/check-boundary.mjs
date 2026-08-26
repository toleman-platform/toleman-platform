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
  process.exit(0);
}

console.error(`${RULE_ID}: ${violations.length} violation(s)\n`);
for (const v of violations) {
  console.error(`  ${v.file}:${v.line}\n    ${v.message}\n`);
}
process.exit(1);
