import { describe, expect, it } from "vitest";
import { cn, pixelToRem, pxToRem, timeAgo } from "./utils";

describe("cn", () => {
  it("joins truthy class names", () => {
    expect(cn("a", "b")).toBe("a b");
  });

  it("drops falsy values", () => {
    expect(cn("a", false, null, undefined, "b")).toBe("a b");
  });

  it("merges conflicting tailwind classes, last wins", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });

  it("keeps non-conflicting classes from both sides", () => {
    expect(cn("text-sm font-medium", "text-lg")).toBe("font-medium text-lg");
  });
});

describe("pixelToRem", () => {
  it("converts standard pixel values to rem", () => {
    expect(pixelToRem(16)).toBe("1rem");
    expect(pixelToRem(14)).toBe("0.875rem");
    expect(pixelToRem(12)).toBe("0.75rem");
    expect(pixelToRem(20)).toBe("1.25rem");
    expect(pixelToRem(24)).toBe("1.5rem");
    // alias verification
    expect(pxToRem(16)).toBe("1rem");
  });

  it("supports options for unit stripping and custom base", () => {
    expect(pixelToRem(24, { unit: false })).toBe("1.5");
    expect(pixelToRem(20, { base: 10 })).toBe("2rem");
  });
});

describe("timeAgo", () => {
  it("returns isoTimestamp when timestamp is invalid", () => {
    expect(timeAgo("not-a-date")).toBe("not-a-date");
  });

  it("handles recent timestamps", () => {
    const nowIso = new Date().toISOString();
    expect(timeAgo(nowIso)).toBe("Just now");
  });

  it("handles epoch 0 correctly", () => {
    const epochZero = new Date(0).toISOString();
    expect(timeAgo(epochZero)).toBe(new Date(0).toLocaleDateString());
  });
});


