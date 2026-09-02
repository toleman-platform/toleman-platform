import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ProgressBar } from "./progress-bar";

describe("ProgressBar", () => {
  it("calculates percentage correctly and sets inner width", () => {
    const { container, rerender } = render(<ProgressBar value={75} max={100} />);
    const bar = container.querySelector(".rounded-full > div");
    expect(bar?.getAttribute("style")).toBe("width: 75%;");

    rerender(<ProgressBar value={1} max={4} />);
    const bar2 = container.querySelector(".rounded-full > div");
    expect(bar2?.getAttribute("style")).toBe("width: 25%;");
  });

  it("clamps percentage between 0 and 100", () => {
    const { container, rerender } = render(<ProgressBar value={150} max={100} />);
    const barOver = container.querySelector(".rounded-full > div");
    expect(barOver?.getAttribute("style")).toBe("width: 100%;");

    rerender(<ProgressBar value={-20} max={100} />);
    const barUnder = container.querySelector(".rounded-full > div");
    expect(barUnder?.getAttribute("style")).toBe("width: 0%;");
  });

  it("supports size variants", () => {
    const { container: smContainer } = render(<ProgressBar value={50} size="sm" />);
    expect(smContainer.querySelector(".h-1\\.5")).toBeTruthy();

    const { container: mdContainer } = render(<ProgressBar value={50} size="md" />);
    expect(mdContainer.querySelector(".h-2")).toBeTruthy();

    const { container: lgContainer } = render(<ProgressBar value={50} size="lg" />);
    expect(lgContainer.querySelector(".h-3")).toBeTruthy();
  });

  it("applies auto semantic tones based on percentage thresholds", () => {
    // >= 80% -> bg-chart-5 (positive)
    const { container: cHigh } = render(<ProgressBar value={85} />);
    expect(cHigh.querySelector(".bg-chart-5")).toBeTruthy();

    // >= 50% -> bg-chart-3 (attention)
    const { container: cMed } = render(<ProgressBar value={60} />);
    expect(cMed.querySelector(".bg-chart-3")).toBeTruthy();

    // < 50% -> bg-destructive (critical)
    const { container: cLow } = render(<ProgressBar value={30} />);
    expect(cLow.querySelector(".bg-destructive")).toBeTruthy();
  });

  it("supports explicit tone overrides", () => {
    const { container: cPos } = render(<ProgressBar value={20} tone="positive" />);
    expect(cPos.querySelector(".bg-chart-5")).toBeTruthy();

    const { container: cAttn } = render(<ProgressBar value={95} tone="attention" />);
    expect(cAttn.querySelector(".bg-chart-3")).toBeTruthy();

    const { container: cCrit } = render(<ProgressBar value={95} tone="critical" />);
    expect(cCrit.querySelector(".bg-destructive")).toBeTruthy();

    const { container: cDef } = render(<ProgressBar value={95} tone="default" />);
    expect(cDef.querySelector(".bg-primary")).toBeTruthy();
  });

  it("displays formatted numeric value when showValue is true", () => {
    render(<ProgressBar value={42} showValue />);
    expect(screen.getByText("42%")).toBeTruthy();
  });

  it("supports custom valueSuffix", () => {
    render(<ProgressBar value={80} showValue valueSuffix="/100" />);
    expect(screen.getByText("80/100")).toBeTruthy();
  });

  it("forwards accessibility attributes and roles", () => {
    render(
      <ProgressBar
        value={60}
        role="progressbar"
        aria-valuenow={60}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    );
    const progressbar = screen.getByRole("progressbar");
    expect(progressbar).toBeTruthy();
    expect(progressbar.getAttribute("aria-valuenow")).toBe("60");
    expect(progressbar.getAttribute("aria-valuemin")).toBe("0");
    expect(progressbar.getAttribute("aria-valuemax")).toBe("100");
  });
});
