import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import PrHistoryPage from "./page";
import type { PullRequest, PrGuardrailFinding } from "@/lib/api";

// Only the API and routing boundaries are mocked; the PR list, its state
// filter and the findings a row expands into are the real ones the page
// renders.
const { targets, prs, getPrGuardrailLog, getPrGuardrailOrgLog, getPrGuardrailFindings, activePrScans } =
  vi.hoisted(() => ({
    targets: vi.fn(),
    prs: vi.fn(),
    getPrGuardrailLog: vi.fn(),
    getPrGuardrailOrgLog: vi.fn(),
    getPrGuardrailFindings: vi.fn(),
    activePrScans: vi.fn(),
  }));

vi.mock("@/lib/api", () => ({
  api: {
    targets,
    prs,
    getPrGuardrailLog,
    getPrGuardrailOrgLog,
    getPrGuardrailFindings,
    activePrScans,
    runPrGuardrailScan: vi.fn(),
    overridePrGuardrail: vi.fn(),
    requestIgnoreFinding: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/pr-history",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

function pr(overrides: Partial<PullRequest> = {}): PullRequest {
  return {
    number: 1,
    title: "a pr",
    author: "dev",
    state: "open",
    created_at: "2026-09-01T00:00:00Z",
    merged_at: null,
    url: "https://github.com/acme/repo/pull/1",
    scan_status: "not scanned",
    latest_scan_id: null,
    new_findings_count: 0,
    highest_new_severity: null,
    ...overrides,
  };
}

// The state filter is answered by the server (see api.prs), so the stub is
// keyed by the state asked for: a stub that returned the same list whatever
// was requested would pass even if the page stopped asking.
function prsByState(byState: Record<string, PullRequest[]>) {
  prs.mockImplementation((_targetId: number, state: string) =>
    Promise.resolve(byState[state] ?? []),
  );
}

function finding(id: number): PrGuardrailFinding {
  return {
    id,
    pr_scan_id: 55,
    tool: "semgrep",
    rule_id: "sql-injection",
    title: `finding ${id}`,
    file_path: "app/db.py",
    line_start: 88,
    severity: "High",
    ignore_status: "none",
    ignore_requested_by: "",
    ignore_requested_reason: "",
    ignore_reviewed_by: "",
    ignore_reviewed_at: null,
  } as PrGuardrailFinding;
}

beforeEach(() => {
  vi.clearAllMocks();
  targets.mockResolvedValue([{ id: 1, name: "repo-a" }]);
  prs.mockResolvedValue([]);
  prs.mockImplementation(() => Promise.resolve([]));
  getPrGuardrailLog.mockResolvedValue([]);
  getPrGuardrailOrgLog.mockResolvedValue({ scans: [], stats: null });
  getPrGuardrailFindings.mockResolvedValue([]);
  activePrScans.mockResolvedValue([]);
});

// A reviewer opening PR History is asking about work in flight. Closed and
// merged PRs are history, and on any repo with a few months behind it they
// push the open ones off the first page.
const MIXED = {
  open: [pr({ number: 1, title: "still open" })],
  merged: [pr({ number: 2, title: "was merged", state: "merged", merged_at: "2026-09-02T00:00:00Z" })],
  closed: [pr({ number: 3, title: "was closed", state: "closed" })],
  all: [
    pr({ number: 1, title: "still open" }),
    pr({ number: 2, title: "was merged", state: "merged", merged_at: "2026-09-02T00:00:00Z" }),
    pr({ number: 3, title: "was closed", state: "closed" }),
  ],
};

describe("PR state filter", () => {
  it("opens on the open PRs only", async () => {
    prsByState(MIXED);

    render(<PrHistoryPage />);

    await screen.findByText(/still open/);
    expect(screen.queryByText(/was merged/)).toBeNull();
    expect(screen.queryByText(/was closed/)).toBeNull();
    expect((screen.getByLabelText("PR state") as HTMLSelectElement).value).toBe("open");
  });

  it("asks the server for the state rather than trimming a fetched page", async () => {
    // GitHub returns PRs newest-created first, so a page fetched for every
    // state and narrowed to open in the client is empty on any repo that
    // closes PRs faster than a page of them is opened.
    prsByState(MIXED);

    render(<PrHistoryPage />);
    await screen.findByText(/still open/);

    expect(prs).toHaveBeenCalledWith(1, "open");

    fireEvent.change(screen.getByLabelText("PR state"), { target: { value: "closed" } });

    await screen.findByText(/was closed/);
    expect(prs).toHaveBeenCalledWith(1, "closed");
  });

  it("shows merged PRs on their own, not lumped in with closed ones", async () => {
    prsByState(MIXED);

    render(<PrHistoryPage />);
    await screen.findByText(/still open/);

    fireEvent.change(screen.getByLabelText("PR state"), { target: { value: "merged" } });

    await screen.findByText(/was merged/);
    expect(screen.queryByText(/was closed/)).toBeNull();
    expect(screen.queryByText(/still open/)).toBeNull();
  });

  it("puts every state back with All", async () => {
    prsByState(MIXED);

    render(<PrHistoryPage />);
    await screen.findByText(/still open/);

    fireEvent.change(screen.getByLabelText("PR state"), { target: { value: "all" } });

    await screen.findByText(/was closed/);
    expect(screen.getByText(/still open/)).toBeTruthy();
  });
});

// The findings are the reason anyone reads this page: a row that reports a
// verdict has to open onto the evidence for it, rather than sending the
// reader to find the same PR again in the audit log below.
describe("expanding a PR into its findings", () => {
  it("expands a scanned PR into the vulnerabilities that scan found", async () => {
    prsByState({
      open: [pr({ number: 1, scan_status: "blocked", latest_scan_id: 55, new_findings_count: 2, highest_new_severity: "High" })],
    });
    getPrGuardrailFindings.mockResolvedValue([finding(7), finding(8)]);

    render(<PrHistoryPage />);
    await screen.findByText(/a pr/);

    expect(screen.queryByText("finding 7")).toBeNull();

    fireEvent.click(screen.getByLabelText("Show findings for PR #1"));

    await screen.findByText("finding 7");
    expect(screen.getByText("finding 8")).toBeTruthy();
    expect(getPrGuardrailFindings).toHaveBeenCalledWith(55);
  });

  it("summarises the findings on the collapsed row so the count is visible without opening it", async () => {
    prsByState({
      open: [pr({ number: 1, scan_status: "blocked", latest_scan_id: 55, new_findings_count: 2, highest_new_severity: "High" })],
    });

    render(<PrHistoryPage />);

    await screen.findByText(/2 net-new vulnerability findings/);
    expect(screen.getByText("High")).toBeTruthy();
  });

  it("does not carry an expanded row across a repo switch", async () => {
    // PR numbers are only unique within a repository. Keyed on the number
    // alone, expanding #1 on one repo left #1 on the next repo open and
    // fetching an unrelated scan's findings the moment the picker changed.
    targets.mockResolvedValue([
      { id: 1, name: "repo-a" },
      { id: 2, name: "repo-b" },
    ]);
    prsByState({
      open: [pr({ number: 1, scan_status: "blocked", latest_scan_id: 55, new_findings_count: 1 })],
    });
    getPrGuardrailFindings.mockResolvedValue([finding(7)]);

    render(<PrHistoryPage />);
    await screen.findByText(/a pr/);

    fireEvent.click(screen.getByLabelText("Show findings for PR #1"));
    await screen.findByText("finding 7");

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "2" } });

    await waitFor(() => expect(screen.queryByText("finding 7")).toBeNull());
    expect(screen.getByLabelText("Show findings for PR #1")).toBeTruthy();
  });

  it("offers no expander on a PR that was never scanned", async () => {
    prsByState({ open: [pr({ number: 1 })] });

    render(<PrHistoryPage />);
    await screen.findByText(/a pr/);

    expect(screen.queryByLabelText("Show findings for PR #1")).toBeNull();
    await waitFor(() => expect(getPrGuardrailFindings).not.toHaveBeenCalled());
  });
});
