import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Stripping `dark:` utilities by hand corrupts the class next to the one it
 * deletes, in two shapes. Deleting ` dark:aria-invalid:ring-destructive/` out
 * of
 *
 *   aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40
 *
 * welds the opacity suffixes into `ring-destructive/2040`; deleting
 * ` dark:bg-input/30 dark:border-input dark:hover:bg-input/` out of
 *
 *   hover:text-accent-foreground dark:bg-input/30 ... dark:hover:bg-input/50
 *
 * welds digits straight onto the identifier as
 * `hover:text-accent-foreground3050`. Both still look like classes, still
 * typecheck, and still pass every component test while matching no Tailwind
 * rule at all -- so the focus ring, the invalid-state ring and the hover text
 * colour silently stop rendering, on every button in the app.
 *
 * Both shapes really shipped, in the same file, and the first version of this
 * guard caught only the first: it was anchored on `/`, which the second shape
 * does not have, and it gated on lines containing "class" or "cva(", which the
 * corrupted lines inside a `cva` variants object do not contain. Hence one
 * rule, anchored on the token rather than the line.
 *
 * The token must look like a Tailwind colour-bearing utility, optionally
 * behind any number of variants, and must then contain either three or more
 * digits after a slash (opacity modifiers are at most two) or a digit welded
 * straight onto a letter (Tailwind always introduces a digit with `-`, `/`,
 * `[` or `.`). Verified against the whole frontend: with the corrupted classes
 * restored, zero occurrences.
 */
const SRC_DIR = join(__dirname, "..", "..");
const TOKEN = /[A-Za-z][\w:./[\]%()&>*'-]*/g;
const COLOUR_UTILITY =
  /^(?:[a-z][a-z-]*:)*(?:bg|text|border|ring|outline|shadow|fill|stroke|divide|placeholder|caret|accent|decoration|from|via|to)-/;
const CORRUPTED = /[a-z][0-9]|\/\d{3,}/;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = join(dir, e.name);
    if (e.isDirectory()) return sourceFiles(full);
    // This file's own docstring spells both bad classes out verbatim.
    if (full === __filename) return [];
    return /\.tsx?$/.test(e.name) ? [full] : [];
  });
}

describe("Tailwind class integrity", () => {
  it("has no class corrupted by a welded utility suffix", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC_DIR)) {
      for (const [i, line] of readFileSync(file, "utf8").split("\n").entries()) {
        // Arbitrary values legitimately put digits next to letters
        // (`w-[calc(100%-2rem)]`, `text-[10px]`), and are always bracketed.
        for (const token of line.replace(/\[[^\]]*\]/g, "").match(TOKEN) ?? []) {
          if (COLOUR_UTILITY.test(token) && CORRUPTED.test(token)) {
            offenders.push(`${file.slice(SRC_DIR.length + 1)}:${i + 1}: ${token}`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
