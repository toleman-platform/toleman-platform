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

  // The outline variant is the most-instantiated button in the product and it
  // lives inside Cards, so grounding it in the page background put it UNDER
  // its own surface -- a recessed hole rather than a raised control, in both
  // themes. Nothing else fails when that reverts: the class is valid, every
  // render test still passes, and the regression is only visible to someone
  // looking at a card. Hence a test on the ground the variant asks for, with
  // globals.css.test.ts holding the other half -- that `--control` is never
  // darker than a surface it sits on.
  it("does not ground the outline variant in the page background", () => {
    render(<Button variant="outline">Export</Button>);
    const className = screen.getByRole("button", { name: "Export" }).className;

    // Matches `bg-background` bare, behind a variant (`hover:bg-background`)
    // and with an opacity modifier (`bg-background/80`), but not a longer
    // utility that merely starts with it.
    expect(className).not.toMatch(/(?<![-\w])bg-background(?![-\w])/);
    expect(className.split(/\s+/)).toContain("bg-control");
  });
});
