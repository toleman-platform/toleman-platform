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

// Mutable per-test so the "History" tab test below can render with
// ?tab=history already selected -- clicking the tab Link doesn't actually
// navigate under this mock, same as every other tab-param test in this
// codebase (see hooks/use-tab-param.test.tsx).
let currentSearch = "";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(currentSearch),
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
    reject_reason: null,
    ...over,
  } as PrGuardrailFinding;
}

beforeEach(() => {
  for (const m of [getPendingIgnoreRequests, getIgnoreRequestHistory, approveIgnore, rejectIgnore, revokeIgnore]) {
    m.mockReset();
  }
  currentSearch = "";
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

  it("requires a typed reason before a rejection can be confirmed", async () => {
    render(<ApprovalQueue />);

    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));
    const confirmButton = (await screen.findByRole("button", { name: "Confirm reject" })) as HTMLButtonElement;
    expect(confirmButton.disabled).toBe(true);
    expect(rejectIgnore).not.toHaveBeenCalled();

    fireEvent.change(screen.getByPlaceholderText("Reason for rejecting"), {
      target: { value: "still exploitable in this context" },
    });
    expect(confirmButton.disabled).toBe(false);

    fireEvent.click(confirmButton);
    expect(rejectIgnore).toHaveBeenCalledWith(7, "still exploitable in this context");
  });

  it("surfaces a failed rejection on the row it belongs to, keeping the typed reason", async () => {
    // Reject is deliberately not gated behind a confirm dialog -- it denies a
    // request without changing what the guardrail enforces -- but it must
    // still report a failure, and not lose what the reviewer already typed.
    rejectIgnore.mockRejectedValue(new Error("network error"));
    render(<ApprovalQueue />);

    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));
    fireEvent.change(screen.getByPlaceholderText("Reason for rejecting"), { target: { value: "not valid here" } });
    fireEvent.click(await screen.findByRole("button", { name: "Confirm reject" }));

    expect(await screen.findByText(/Nothing was changed: network error/i)).toBeDefined();
    expect((screen.getByPlaceholderText("Reason for rejecting") as HTMLInputElement).value).toBe("not valid here");
  });

  it("shows the recorded reject reason in the History tab", async () => {
    currentSearch = "tab=history";
    getIgnoreRequestHistory.mockResolvedValue({
      items: [
        finding({
          ignore_status: "rejected",
          ignore_reviewed_by: "sec@example.com",
          reject_reason: "risk accepted elsewhere already",
        }),
      ],
      total: 1,
    });
    render(<ApprovalQueue />);

    expect(await screen.findByText(/Reason: risk accepted elsewhere already/i)).toBeDefined();
  });

  it("labels a rejected row with no stored reason instead of rendering it blank", async () => {
    // A row rejected before this column existed has no reason to show --
    // must read as "not recorded", never as an empty/blank line that looks
    // like the reviewer typed nothing.
    currentSearch = "tab=history";
    getIgnoreRequestHistory.mockResolvedValue({
      items: [finding({ ignore_status: "rejected", ignore_reviewed_by: "sec@example.com", reject_reason: null })],
      total: 1,
    });
    render(<ApprovalQueue />);

    expect(await screen.findByText(/Reason: not recorded/i)).toBeDefined();
  });
});
