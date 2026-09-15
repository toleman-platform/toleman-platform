import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Contrast is a property of a PAIR of tokens, so no component test can hold
 * it: button.test.tsx can prove the outline variant asks for `bg-control`,
 * but only this file can prove that whatever `--control` holds is not darker
 * than the card the button sits on. That inversion is exactly the defect
 * being fixed here -- the variant was `bg-background`, the page colour, on a
 * lighter `--card`, so the most-used button in the product rendered as a hole
 * punched in the surface instead of a control resting on it (0.0090 against
 * 0.0142 in dark; 0.9284 against 1.0000 in light, the same inversion the
 * other way up).
 *
 * Every number below is computed from the hex in globals.css with the WCAG
 * relative-luminance formula, not asserted against a figure copied out of the
 * stylesheet, so repainting the palette re-measures it rather than agreeing
 * with itself. The assertions are relationships -- "a control's ground is
 * never darker than a surface it can sit on", "a control's boundary clears
 * 3:1" -- so a deliberate repaint stays free to move the values.
 */

const CSS = readFileSync(join(__dirname, "globals.css"), "utf8")
  // Comments quote token values and ratios verbatim; parsing them as
  // declarations would read the history as if it were the current palette.
  .replace(/\/\*[\s\S]*?\*\//g, "");

type Theme = Record<string, string>;

function declarations(selector: RegExp): Theme {
  const block = CSS.match(selector);
  if (!block) throw new Error(`globals.css: no block matching ${selector}`);
  const out: Theme = {};
  for (const [, name, value] of block[1].matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)) {
    out[name] = value.trim();
  }
  return out;
}

// `:root {` and `:root[data-theme="light"] {`. The light block only lists the
// tokens whose value actually changes, so it layers over the dark one -- the
// same way the cascade resolves it in the browser.
const DARK = declarations(/(?:^|\n):root\s*\{([^}]*)\}/);
const LIGHT: Theme = { ...DARK, ...declarations(/:root\[data-theme="light"\]\s*\{([^}]*)\}/) };
const THEMES: [string, Theme][] = [
  ["dark", DARK],
  ["light", LIGHT],
];

/** Resolves `--a: var(--b)` chains down to the literal that backs them. */
function hex(theme: Theme, token: string): string {
  let value: string | undefined = theme[token];
  for (let hop = 0; hop < 8; hop++) {
    if (value === undefined) break;
    const indirect = /^var\(\s*--([\w-]+)\s*\)$/.exec(value);
    if (!indirect) break;
    value = theme[indirect[1]];
  }
  if (value === undefined) throw new Error(`globals.css: --${token} is not defined`);
  if (!/^#[0-9a-f]{6}$/i.test(value)) {
    throw new Error(`globals.css: --${token} is ${value}, expected a 6-digit hex`);
  }
  return value;
}

function luminance(value: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(value.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * Every ground a control can be drawn on. `--background` is the page itself,
 * the rest are surfaces stacked on it, and `--control`/`--control-hover` are
 * the control's own grounds, which its boundary and its label still have to
 * survive.
 */
const GROUNDS = [
  "background",
  "card",
  "popover",
  "secondary",
  "muted",
  "accent",
  "sidebar",
  "control",
  "control-hover",
];

/** The subset of those that a control can find itself sitting on top of. */
const SURFACES = ["background", "card", "popover", "secondary", "muted", "accent", "sidebar"];

for (const [name, theme] of THEMES) {
  describe(`${name} theme tokens`, () => {
    it("keeps a control's ground level with or above every surface it sits on", () => {
      const control = luminance(hex(theme, "control"));
      const sunken = SURFACES.filter((s) => control < luminance(hex(theme, s))).map(
        (s) => `--control ${hex(theme, "control")} is darker than --${s} ${hex(theme, s)}`,
      );
      expect(sunken).toEqual([]);
    });

    it("lifts a control's ground clear of the page background", () => {
      // The defect this whole change exists for: a `--control` equal to (or
      // below) `--background` is a control painted in the page colour, which
      // reads as a hole in whatever surface it was placed on.
      expect(luminance(hex(theme, "control"))).toBeGreaterThan(luminance(hex(theme, "background")));
    });

    it("never lets the hover ground sink below the page background", () => {
      // Dark can keep lifting on hover; light cannot, because white is the
      // ceiling and the hover has to darken. The invariant that holds in both
      // is that hovering must not push the control under the page around it.
      expect(luminance(hex(theme, "control-hover"))).toBeGreaterThanOrEqual(
        luminance(hex(theme, "background")),
      );
    });

    it("draws a control's boundary at 3:1 on every ground", () => {
      // WCAG 1.4.11. `--input` is the edge of a native select/input and of the
      // outline Button; on a white card that edge is the only thing that
      // separates the control from the surface.
      const input = hex(theme, "input");
      const failures = GROUNDS.filter((g) => ratio(input, hex(theme, g)) < 3).map(
        (g) => `--input on --${g}: ${ratio(input, hex(theme, g)).toFixed(2)}:1`,
      );
      expect(failures).toEqual([]);
    });

    it("reads body text at 4.5:1 on every ground", () => {
      // `--muted-foreground` on `--muted`/`--secondary` is the pair the app
      // leans on hardest: every hint line, chip and secondary label.
      const failures: string[] = [];
      for (const text of ["foreground", "muted-foreground"]) {
        for (const ground of GROUNDS) {
          const measured = ratio(hex(theme, text), hex(theme, ground));
          if (measured < 4.5) failures.push(`--${text} on --${ground}: ${measured.toFixed(2)}:1`);
        }
      }
      expect(failures).toEqual([]);
    });
  });
}
