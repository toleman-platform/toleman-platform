import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ShieldAlert } from "lucide-react";
import { Icon } from "./icon";

describe("Icon component", () => {
  it("renders with default size (md = 16px) and aria-hidden", () => {
    const { container } = render(<Icon icon={ShieldAlert} />);
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
    expect(svg?.getAttribute("class")).toContain("h-4");
    expect(svg?.getAttribute("class")).toContain("w-4");
    expect(svg?.getAttribute("aria-hidden")).toBe("true");
  });

  it("applies semantic size variants correctly", () => {
    const { container: cXs } = render(<Icon icon={ShieldAlert} size="xs" />);
    expect(cXs.querySelector("svg")?.getAttribute("class")).toContain("h-3");
    expect(cXs.querySelector("svg")?.getAttribute("class")).toContain("w-3");

    const { container: cSm } = render(<Icon icon={ShieldAlert} size="sm" />);
    expect(cSm.querySelector("svg")?.getAttribute("class")).toContain("h-3.5");
    expect(cSm.querySelector("svg")?.getAttribute("class")).toContain("w-3.5");

    const { container: cLg } = render(<Icon icon={ShieldAlert} size="lg" />);
    expect(cLg.querySelector("svg")?.getAttribute("class")).toContain("h-5");
    expect(cLg.querySelector("svg")?.getAttribute("class")).toContain("w-5");

    const { container: cXl } = render(<Icon icon={ShieldAlert} size="xl" />);
    expect(cXl.querySelector("svg")?.getAttribute("class")).toContain("h-6");
    expect(cXl.querySelector("svg")?.getAttribute("class")).toContain("w-6");

    const { container: c2Xl } = render(<Icon icon={ShieldAlert} size="2xl" />);
    expect(c2Xl.querySelector("svg")?.getAttribute("class")).toContain("h-8");
    expect(c2Xl.querySelector("svg")?.getAttribute("class")).toContain("w-8");
  });

  it("applies semantic color tones", () => {
    const { container } = render(<Icon icon={ShieldAlert} tone="destructive" />);
    expect(container.querySelector("svg")?.getAttribute("class")).toContain("text-destructive");
  });

  it("sets accessible role and aria-label when label is provided", () => {
    render(<Icon icon={ShieldAlert} label="Security alert badge" />);
    const svg = screen.getByRole("img", { name: "Security alert badge" });
    expect(svg).toBeTruthy();
    expect(svg.getAttribute("aria-hidden")).toBeNull();
  });

  it("supports wrapping child icon elements via children", () => {
    render(
      <Icon size="lg" tone="primary">
        <ShieldAlert data-testid="child-icon" />
      </Icon>
    );
    const svg = screen.getByTestId("child-icon");
    expect(svg.getAttribute("class")).toContain("h-5");
    expect(svg.getAttribute("class")).toContain("w-5");
    expect(svg.getAttribute("class")).toContain("text-primary");
  });
});
