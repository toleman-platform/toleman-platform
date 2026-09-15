import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Button } from "./button";

describe("Button", () => {
  // core lows: `transition-all` animates every animatable property, not just
  // the ones this component's variants actually change, and never turns off
  // under prefers-reduced-motion. Naming the properties and adding the
  // motion-reduce guard are both regressions this test would catch.
  it("names its transition properties instead of transitioning everything", () => {
    render(<Button>Save</Button>);
    const button = screen.getByRole("button", { name: "Save" });
    expect(button.className).not.toMatch(/(?<![-\w])transition-all(?![-\w])/);
  });

  it("disables its transition under prefers-reduced-motion", () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole("button", { name: "Save" }).className).toContain("motion-reduce:transition-none");
  });
});
