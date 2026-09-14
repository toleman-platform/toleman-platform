import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeverityChip } from "./severity-chip";

describe("SeverityChip", () => {
  it("renders each of the 5 severity tiers with proper normalization", () => {
    const { rerender } = render(<SeverityChip severity="critical" />);
    expect(screen.getByText("Critical")).toBeTruthy();

    rerender(<SeverityChip severity="high" />);
    expect(screen.getByText("High")).toBeTruthy();

    rerender(<SeverityChip severity="medium" />);
    expect(screen.getByText("Medium")).toBeTruthy();

    rerender(<SeverityChip severity="low" />);
    expect(screen.getByText("Low")).toBeTruthy();

    // "informational", matching the real tier name lib/severity.ts and the
    // backend both use (Finding.severity), not the shorter "info" this
    // component used to hand-roll on its own.
    rerender(<SeverityChip severity="informational" />);
    expect(screen.getByText("Informational")).toBeTruthy();
  });

  it("renders count display when count is provided", () => {
    const { rerender } = render(<SeverityChip severity="High" count={5} />);
    expect(screen.getByText("High")).toBeTruthy();
    expect(screen.getByText("(5)")).toBeTruthy();

    rerender(<SeverityChip severity="High" count={0} />);
    expect(screen.getByText("(0)")).toBeTruthy();
  });

  it("does not render count element when count is undefined", () => {
    const { container } = render(<SeverityChip severity="Critical" />);
    expect(screen.getByText("Critical")).toBeTruthy();
    expect(container.textContent).toBe("Critical");
  });

  it("renders dot variant with indicator span", () => {
    const { container } = render(<SeverityChip severity="Critical" variant="dot" count={3} />);
    expect(screen.getByText("Critical")).toBeTruthy();
    expect(screen.getByText("(3)")).toBeTruthy();
    const dot = container.querySelector(".bg-destructive");
    expect(dot).toBeTruthy();
    expect(dot?.getAttribute("aria-hidden")).toBe("true");
  });

  it("renders default subtle badge variant with border and background styling", () => {
    const { container } = render(<SeverityChip severity="Critical" />);
    const badge = container.querySelector("span");
    expect(badge?.className).toContain("border");
    expect(badge?.className).toContain("text-destructive");
  });

  it("applies size classes correctly", () => {
    const { container: smContainer } = render(<SeverityChip severity="Low" size="sm" />);
    expect(smContainer.querySelector("span")?.className).toContain("text-[10px]");

    const { container: mdContainer } = render(<SeverityChip severity="Low" size="md" />);
    expect(mdContainer.querySelector("span")?.className).toContain("text-xs");

    const { container: lgContainer } = render(<SeverityChip severity="Low" size="lg" />);
    expect(lgContainer.querySelector("span")?.className).toContain("font-semibold");
  });

  it("handles unknown severity fallback gracefully", () => {
    render(<SeverityChip severity="unranked" />);
    expect(screen.getByText("Unranked")).toBeTruthy();
  });

  // Regression for the dot variant carrying its own color vocabulary that
  // disagreed with lib/severity's: Low used to get a private accent
  // (chart-2) here while every other severity map treats Low the same
  // neutral way it treats Informational. Both should render the identical
  // neutral dot now that SeverityChip reads SEVERITY_DOT_COLOR instead of a
  // hand-rolled copy of it.
  it("colors the Low dot the same neutral tone as Informational", () => {
    const { container: low } = render(<SeverityChip severity="Low" variant="dot" />);
    const { container: info } = render(<SeverityChip severity="Informational" variant="dot" />);
    expect(low.querySelector(".bg-muted-foreground")).toBeTruthy();
    expect(info.querySelector(".bg-muted-foreground")).toBeTruthy();
    expect(low.querySelector(".bg-chart-2")).toBeNull();
  });
});
