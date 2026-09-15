import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Stripping `dark:` utilities by hand is easy to get subtly wrong: deleting
 * ` dark:aria-invalid:ring-destructive/` out of
 *
 *   aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40
 *
 * welds the two opacity suffixes together into
 * `aria-invalid:ring-destructive/2040` -- which still looks like a class,
 * still typechecks, still passes every component test, and silently renders
 * nothing. The invalid-state ring just disappears, and no existing check in
 * this repo would have said a word.
 *
 * Tailwind opacity modifiers are at most two digits (or a bracketed arbitrary
 * value), so three or more digits after the slash means two suffixes were
 * glued together. The pattern deliberately requires a hyphenated utility
 * before the slash so that prose and data keep passing: "100/100" in a score,
 * "25/50/100" in a comment, and ".../pull/238?tab=files" in a URL are all
 * legitimate and must not trip this.
 */
const SRC_DIR = join(__dirname, "..", "..");
const GLUED_OPACITY = /(?:[a-z][\w.-]*:)*[a-z][\w]*(?:-[\w.]+)+\/\d{3,}(?![\w/])/g;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return sourceFiles(full);
    // This file's own docstring spells the bad class out verbatim.
    if (full === __filename) return [];
    return /\.tsx?$/.test(e.name) ? [full] : [];
  });
}

describe("Tailwind class integrity", () => {
  it("has no glued opacity modifier anywhere in the frontend source", () => {
    const offenders = sourceFiles(SRC_DIR).flatMap((file) =>
      (readFileSync(file, "utf8").match(GLUED_OPACITY) ?? []).map(
        (hit) => `${file.slice(SRC_DIR.length + 1)}: ${hit}`,
      ),
    );
    expect(offenders).toEqual([]);
  });
});
