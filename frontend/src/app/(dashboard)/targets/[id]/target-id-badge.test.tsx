import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { TargetIdBadge } from "./target-id-badge";

describe("TargetIdBadge", () => {
  beforeEach(() => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
  });

  it("shows the target ID", () => {
    render(<TargetIdBadge targetId={42} />);
    expect(screen.getByText("ID 42")).toBeTruthy();
  });

  it("copies the ID as a plain number string, not a formatted label", async () => {
    render(<TargetIdBadge targetId={42} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /copy target id 42/i }));
    });
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("42");
  });

  it("shows brief copied feedback after copying", async () => {
    render(<TargetIdBadge targetId={7} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button"));
    });
    await waitFor(() => expect(screen.getByRole("button").innerHTML).toContain("svg"));
  });
});
