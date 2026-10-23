import { describe, expect, it } from "vitest";
import { localRedirectPath } from "./local-redirect";

describe("localRedirectPath", () => {
  it.each([null, undefined, "", "relative", "//evil.example", "/\\evil.example", "/a/..//evil.example", "javascript:alert(1)", "/\n/evil.example", "/\t/evil.example", "https://evil.example"])("rejects %s", (value) => {
    expect(localRedirectPath(value)).toBe("/");
  });

  it.each(["/", "/findings?severity=Critical", "/pr-history?target_id=2&ignore_finding=144#review", "/targets?q=hello%20world"])("preserves %s", (value) => {
    expect(localRedirectPath(value)).toBe(value);
  });
});
