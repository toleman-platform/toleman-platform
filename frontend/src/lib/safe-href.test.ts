import { describe, expect, it } from "vitest";
import { safeHref } from "./utils";

// (#275) Snyk Code flagged two <a href={...}> sites as DOM-based XSS; both
// were false positives on inspection (a hardcoded prefix, a server-built
// template), but the underlying pattern -- a dynamic value reaching href --
// is real across 11 sites in this app, and "safe today by local invariant"
// is exactly the kind of thing that regresses silently. This is the shared
// enforcement the report recommended killing the pattern with.

describe("safeHref", () => {
  it("allows a plain https URL", () => {
    expect(safeHref("https://github.com/toleman-platform/toleman-platform")).toBe(
      "https://github.com/toleman-platform/toleman-platform",
    );
  });

  it("allows a plain http URL", () => {
    expect(safeHref("http://example.com")).toBe("http://example.com");
  });

  it("rejects javascript: URLs", () => {
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
  });

  it("rejects javascript: obfuscated with embedded control characters", () => {
    // The WHATWG URL parser strips tabs/newlines before reading the scheme,
    // same as a real browser does -- a hand-rolled regex checking for a
    // leading "javascript:" would miss this the way the flagged code paths
    // originally could have, if their local invariants ever slipped.
    expect(safeHref("java\tscript:alert(1)")).toBeUndefined();
    expect(safeHref("java\nscript:alert(1)")).toBeUndefined();
  });

  it("rejects data: URLs", () => {
    expect(safeHref("data:text/html,<script>alert(1)</script>")).toBeUndefined();
  });

  it("rejects vbscript: URLs", () => {
    expect(safeHref("vbscript:msgbox(1)")).toBeUndefined();
  });

  it("returns undefined for null, undefined, and empty string", () => {
    expect(safeHref(null)).toBeUndefined();
    expect(safeHref(undefined)).toBeUndefined();
    expect(safeHref("")).toBeUndefined();
  });

  it("returns undefined rather than throwing for a malformed value", () => {
    expect(() => safeHref("not a url at all \0")).not.toThrow();
  });

  it("allows a relative path (same-origin, resolved against the current page)", () => {
    expect(safeHref("/targets/7")).toBe("/targets/7");
  });

  it("preserves the exact input string on success, not a normalized form", () => {
    // Callers render the returned value directly; a helper that "fixes"
    // valid URLs on the way through would be a surprise no caller asked for.
    const url = "https://github.com/toleman-platform/toleman-platform/pull/238?tab=files";
    expect(safeHref(url)).toBe(url);
  });
});
