import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AlertBanner } from "./alert-banner";
import { Button } from "./button";

describe("AlertBanner", () => {
  it("renders with role='alert' and default info tone", () => {
    render(<AlertBanner>System maintenance scheduled for tonight.</AlertBanner>);
    const banner = screen.getByRole("alert");
    expect(banner).toBeTruthy();
    expect(banner.textContent).toContain("System maintenance scheduled for tonight.");
    expect(banner.className).toContain("border-primary/30");
    expect(banner.className).toContain("bg-primary/10");
  });

  it("renders critical tone with destructive styling and icon", () => {
    const { container } = render(
      <AlertBanner tone="critical" title="Security Breach">
        Unauthorized access detected.
      </AlertBanner>
    );
    const banner = screen.getByRole("alert");
    expect(banner.className).toContain("border-destructive/30");
    expect(banner.className).toContain("bg-destructive/15");
    expect(screen.getByText("Security Breach")).toBeTruthy();
    expect(screen.getByText("Unauthorized access detected.")).toBeTruthy();
    const svg = container.querySelector("svg");
    expect(svg).toBeTruthy();
    expect(svg?.getAttribute("class")).toContain("text-destructive");
  });

  it("renders warning (attention) tone correctly", () => {
    const { container } = render(
      <AlertBanner tone="warning" title="Token Expiring">
        GitHub PAT will expire in 2 days.
      </AlertBanner>
    );
    const banner = screen.getByRole("alert");
    expect(banner.className).toContain("border-chart-3/30");
    expect(banner.className).toContain("bg-chart-3/15");
    expect(screen.getByText("Token Expiring")).toBeTruthy();
    const svg = container.querySelector("svg");
    expect(svg?.getAttribute("class")).toContain("text-chart-3");
  });

  it("renders positive tone correctly", () => {
    const { container } = render(
      <AlertBanner tone="positive" title="Scan Complete">
        No new vulnerabilities found.
      </AlertBanner>
    );
    const banner = screen.getByRole("alert");
    expect(banner.className).toContain("border-chart-5/30");
    expect(banner.className).toContain("bg-chart-5/15");
    expect(screen.getByText("Scan Complete")).toBeTruthy();
    const svg = container.querySelector("svg");
    expect(svg?.getAttribute("class")).toContain("text-chart-5");
  });

  it("renders action slot when provided", () => {
    render(
      <AlertBanner
        tone="warning"
        action={<Button size="sm">Renew</Button>}
      >
        Your credentials need review.
      </AlertBanner>
    );
    expect(screen.getByRole("button", { name: "Renew" })).toBeTruthy();
  });

  it("applies custom className", () => {
    render(
      <AlertBanner className="custom-test-class">
        Custom class notice
      </AlertBanner>
    );
    expect(screen.getByRole("alert").className).toContain("custom-test-class");
  });
});
