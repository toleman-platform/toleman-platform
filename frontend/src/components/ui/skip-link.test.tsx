import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SkipLink } from "./skip-link";

describe("SkipLink", () => {
  it("points at the given landmark id", () => {
    render(<SkipLink targetId="main-content" />);
    const link = screen.getByRole("link", { name: "Skip to main content" });
    expect(link.getAttribute("href")).toBe("#main-content");
  });

  it("is visually hidden until it receives focus", () => {
    // The whole point: a sighted keyboard user tabbing through the page
    // should not see this take up space until it's the thing focus landed
    // on, but it must still be reachable and clearly visible at that point.
    render(<SkipLink targetId="main-content" />);
    const link = screen.getByRole("link", { name: "Skip to main content" });
    expect(link.className).toContain("sr-only");
    expect(link.className).toContain("focus:not-sr-only");
  });

  it("supports custom link text", () => {
    render(<SkipLink targetId="results">Skip to results</SkipLink>);
    expect(screen.getByRole("link", { name: "Skip to results" })).not.toBeNull();
  });
});
