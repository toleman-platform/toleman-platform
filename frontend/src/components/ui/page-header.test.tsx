import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { PageHeader } from "./page-header";
import { Button } from "./button";
import { Badge } from "./badge";

describe("PageHeader", () => {
  it("renders title inside h1 heading", () => {
    render(<PageHeader title="Vulnerability Dashboard" />);
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Vulnerability Dashboard");
  });

  it("renders description when provided", () => {
    render(
      <PageHeader
        title="Targets"
        description="Manage repository integration and scan cadences."
      />
    );
    expect(
      screen.getByText("Manage repository integration and scan cadences.")
    ).toBeTruthy();
  });

  it("renders actions slot", () => {
    render(
      <PageHeader
        title="Scans"
        actions={
          <>
            <Button variant="outline">Export</Button>
            <Button>New Scan</Button>
          </>
        }
      />
    );
    expect(screen.getByRole("button", { name: "Export" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "New Scan" })).toBeTruthy();
  });

  it("renders badge or breadcrumbs slot", () => {
    render(
      <PageHeader
        title="Repository Settings"
        badge={<Badge variant="secondary">Production</Badge>}
      />
    );
    expect(screen.getByText("Production")).toBeTruthy();
  });

  it("renders complex breadcrumb navigation in description or slot", () => {
    render(
      <PageHeader
        title="toleman-platform"
        description={
          <span aria-label="Breadcrumbs" className="flex gap-1 text-xs">
            <span>Workspaces</span> / <span>Security</span>
          </span>
        }
      />
    );
    expect(screen.getByLabelText("Breadcrumbs")).toBeTruthy();
    expect(screen.getByText("Workspaces")).toBeTruthy();
  });

  it("forwards custom className and attributes", () => {
    const { container } = render(
      <PageHeader title="Audit Log" className="border-b" data-testid="custom-header" />
    );
    const element = screen.getByTestId("custom-header");
    expect(element.className).toContain("border-b");
    expect(container.querySelector("h1")).toBeTruthy();
  });
});
