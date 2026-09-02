import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusBadge } from "./status-badge";

describe("StatusBadge", () => {
  it("renders status variants correctly", () => {
    const statuses = [
      { status: "running", label: "Running" },
      { status: "completed", label: "Completed" },
      { status: "failed", label: "Failed" },
      { status: "blocked", label: "Blocked" },
      { status: "queued", label: "Queued" },
      { status: "pending", label: "Pending" },
      { status: "passed", label: "Passed" },
      { status: "unknown", label: "Unknown" },
    ] as const;

    for (const { status, label } of statuses) {
      const { unmount } = render(<StatusBadge status={status} />);
      expect(screen.getByText(label)).toBeTruthy();
      unmount();
    }
  });

  it("applies animate-spin animation on running status icon", () => {
    const { container, rerender } = render(<StatusBadge status="running" />);
    const icon = container.querySelector("svg");
    expect(icon?.getAttribute("class")).toContain("animate-spin");

    rerender(<StatusBadge status="completed" />);
    const completedIcon = container.querySelector("svg");
    expect(completedIcon?.getAttribute("class")).not.toContain("animate-spin");
  });

  it("supports custom label override", () => {
    render(<StatusBadge status="running" label="Processing 4/10" />);
    expect(screen.getByText("Processing 4/10")).toBeTruthy();
    expect(screen.queryByText("Running")).toBeNull();
  });

  it("handles case-insensitive status values", () => {
    render(<StatusBadge status="FAILED" />);
    expect(screen.getByText("Failed")).toBeTruthy();
  });

  it("applies size variants correctly", () => {
    const { container: smContainer } = render(<StatusBadge status="queued" size="sm" />);
    expect(smContainer.querySelector("span")?.className).toContain("text-[10px]");

    const { container: mdContainer } = render(<StatusBadge status="queued" size="md" />);
    expect(mdContainer.querySelector("span")?.className).toContain("text-xs");
  });

  it("falls back gracefully for unrecognized statuses", () => {
    render(<StatusBadge status="custom_unknown_state" />);
    expect(screen.getByText("Unknown")).toBeTruthy();
  });
});
