import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ShieldCheck } from "lucide-react";
import { StatCard, StatGrid } from "./stat-card";

describe("StatCard", () => {
  it("renders label and value accurately", () => {
    render(<StatCard label="Total Findings" value={142} />);
    expect(screen.getByText("Total Findings")).toBeTruthy();
    expect(screen.getByText("142")).toBeTruthy();
  });

  it("handles unknown posture flag correctly", () => {
    render(
      <StatCard
        label="AIBOM Models"
        value={0}
        unknown={true}
        unknownHint="Not yet analyzed"
      />
    );
    expect(screen.getByText("—")).toBeTruthy();
    expect(screen.queryByText("0")).toBeNull();
    expect(screen.getByText("Not yet analyzed")).toBeTruthy();
  });

  it("renders secondary hint text when provided", () => {
    render(
      <StatCard
        label="Critical CVEs"
        value={3}
        hint="+2 since yesterday"
      />
    );
    expect(screen.getByText("+2 since yesterday")).toBeTruthy();
  });

  it("applies semantic tone color classes to value", () => {
    const { rerender } = render(<StatCard label="Clean" value={10} tone="positive" />);
    expect(screen.getByText("10").className).toContain("text-chart-5");

    rerender(<StatCard label="Attention" value={5} tone="attention" />);
    expect(screen.getByText("5").className).toContain("text-chart-3");

    rerender(<StatCard label="Critical" value={2} tone="critical" />);
    expect(screen.getByText("2").className).toContain("text-destructive");

    rerender(<StatCard label="Default" value={1} tone="default" />);
    expect(screen.getByText("1").className).toContain("text-foreground");
  });

  it("renders optional icon with custom class", () => {
    const { container } = render(
      <StatCard
        label="Score"
        value="A+"
        icon={ShieldCheck}
        iconClass="text-chart-5"
      />
    );
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
  });

  it("wraps in a link when href is provided", () => {
    render(
      <StatCard
        label="Active Scans"
        value={4}
        href="/scans?status=running"
      />
    );
    const link = screen.getByRole("link");
    expect(link.getAttribute("href")).toBe("/scans?status=running");
    expect(screen.getByText("Active Scans")).toBeTruthy();
  });
});

describe("StatGrid", () => {
  it("renders grid container with default 4 columns", () => {
    const { container } = render(
      <StatGrid>
        <div>Stat 1</div>
        <div>Stat 2</div>
      </StatGrid>
    );
    expect(container.firstChild).toBeTruthy();
    expect((container.firstChild as HTMLElement).className).toContain("lg:grid-cols-4");
  });

  it("supports columns configuration", () => {
    const { container } = render(
      <StatGrid columns={3}>
        <div>Stat 1</div>
      </StatGrid>
    );
    expect((container.firstChild as HTMLElement).className).toContain("lg:grid-cols-3");
  });
});
