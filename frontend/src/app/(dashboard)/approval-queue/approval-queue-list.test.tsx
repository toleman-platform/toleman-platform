import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { ApprovalQueue } from "./approval-queue-list";
import type { PrGuardrailFinding } from "@/lib/api";

/**
 * Approving permanently suppresses a security finding and revoking reverses a
 * prior approval. Both used to be one unguarded click wrapped in
 * `try`/`finally` with no `catch`: on failure the spinner cleared, the row did
 * not change, and the reviewer got no signal at all -- so the honest read of
 * the screen was "my click didn't register".
 */
const { getPendingIgnoreRequests, getIgnoreRequestHistory, approveIgnore, rejectIgnore, revokeIgnore } = vi.hoisted(
  () => ({
    getPendingIgnoreRequests: vi.fn(),
    getIgnoreRequestHistory: vi.fn(),
    approveIgnore: vi.fn(),
    rejectIgnore: vi.fn(),
    revokeIgnore: vi.fn(),
  }),
);

vi.mock("@/lib/api", () => ({
  api: { getPendingIgnoreRequests, getIgnoreRequestHistory, approveIgnore, rejectIgnore, revokeIgnore },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/approval-queue",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

function finding(over: Partial<PrGuardrailFinding> = {}): PrGuardrailFinding {
  return {
    id: 7,
    pr_scan_id: 1,
    tool: "semgrep",
    rule_id: "python.lang.security.audit.exec-detected",
    title: "exec() with user input",
    file_path: "app/main.py",
    line_start: 12,
    severity: "Critical",
    ignore_status: "requested",
    ignore_requested_by: "dev@example.com",
    ignore_requested_reason: "false positive, input is a literal",
    ignore_reviewed_by: "",
    ignore_reviewed_at: null,
    ...over,
  } as PrGuardrailFinding;
}

beforeEach(() => {
  for (const m of [getPendingIgnoreRequests, getIgnoreRequestHistory, approveIgnore, rejectIgnore, revokeIgnore]) {
    m.mockReset();
  }
  getPendingIgnoreRequests.mockResolvedValue({ items: [finding()], total: 1 });
  getIgnoreRequestHistory.mockResolvedValue({ items: [], total: 0 });
});

describe("ApprovalQueue", () => {
  it("does not approve on a single click", async () => {
    render(<ApprovalQueue />);

    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));

    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/stops blocking this pull request/i)).toBeDefined();
    expect(approveIgnore).not.toHaveBeenCalled();
  });

  it("surfaces a failed approval instead of clearing silently", async () => {
    approveIgnore.mockRejectedValue(new Error("403 not a security reviewer"));
    render(<ApprovalQueue />);

    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    fireEvent.click(await screen.findByRole("button", { name: "Approve ignore" }));

    // The failure is stated on the row *and* repeated inside the dialog,
    // which stays open rather than closing over an unchanged row.
    expect((await screen.findAllByText(/403 not a security reviewer/)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Nothing was changed/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("alertdialog")).not.toBeNull();
  });

  it("surfaces a failed rejection on the row it belongs to", async () => {
    // Reject is deliberately not gated behind a dialog -- it denies a request
    // without changing what the guardrail enforces -- but it must still report.
    rejectIgnore.mockRejectedValue(new Error("network error"));
    render(<ApprovalQueue />);

    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));

    expect(await screen.findByText(/Nothing was changed: network error/i)).toBeDefined();
  });
});
