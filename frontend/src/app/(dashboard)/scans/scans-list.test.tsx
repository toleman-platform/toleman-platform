import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen } from "@testing-library/react";
import { ScansList } from "./scans-list";
import type { Target } from "@/lib/api";
import { renderWithWorkspace } from "@/test/render-with-workspace";

/**
 * (core H5) Bulk scan dispatch used to report its own outcome as one plain
 * `<p className="text-xs text-muted-foreground">` line -- visually identical
 * whether every target dispatched cleanly or half the batch hit a rate
 * limit, and silent to assistive tech either way. These tests pin the
 * honest replacement: a batch that partially failed reads (and is
 * announced) differently from one that fully succeeded or fully failed,
 * using the same `AlertBanner` every other write-outcome in this codebase
 * renders through (see finding-detail-drawer.test.tsx's State Updated /
 * Triage Failed pair).
 */
const { runScan, activeScans, workspaces } = vi.hoisted(() => ({
  runScan: vi.fn(),
  activeScans: vi.fn(),
  workspaces: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { runScan, activeScans, workspaces },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/scans",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

function target(over: Partial<Target> = {}): Target {
  return {
    id: 1,
    workspace_id: 1,
    name: "svc",
    repo_url: "https://github.com/acme/svc",
    default_branch: "main",
    // Non-Prod by default: Prod routes through ConfirmDialog first, which
    // these tests are not exercising.
    label: "Internal",
    criticality_weight: 2,
    groups: [],
    pipeline_integrated: false,
    pipeline_pr_url: null,
    is_ai_repo: false,
    is_ai_repo_signals: "",
    is_ai_repo_override: null,
    is_ai_repo_effective: false,
    enforcement_mode: null,
    api_base_url: null,
    diff_scoped_pr_scans: false,
    dependency_sync_status: null,
    dependency_sync_error: null,
    dependency_sync_at: null,
    dependency_component_count: null,
    is_active: true,
    deactivated_at: null,
    deleted_at: null,
    ...over,
  } as Target;
}

// Selects a single named tool for the bulk dispatch rather than leaving the
// default "All tools" in place -- that fans one target out into a runScan
// call per SCAN_TOOLS entry, which only adds unrelated sleeps between calls
// to advance past below.
function selectBulkTool(value: string) {
  fireEvent.change(screen.getByLabelText("Tool to run on selected targets"), { target: { value } });
}

// scans-list.tsx spaces dispatched requests by DISPATCH_SPACING_MS (700ms,
// real backend rate-limit headroom) via a bare `setTimeout`-based sleep; one
// advance is needed per target in the batch for the loop to reach the final
// summary state.
async function flushDispatch(times: number) {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(700);
    });
  }
}

beforeEach(() => {
  vi.useFakeTimers();
  runScan.mockReset();
  activeScans.mockReset();
  activeScans.mockResolvedValue({});
  workspaces.mockReset();
  workspaces.mockResolvedValue([]);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ScansList bulk dispatch outcome", () => {
  it("announces a fully successful dispatch as a positive, live-region banner", async () => {
    runScan.mockResolvedValue({ scan_id: 1, status: "running" });
    const targets = [target({ id: 1, name: "svc-a" }), target({ id: 2, name: "svc-b" })];

    renderWithWorkspace(<ScansList targets={targets} summary={{}} />);

    fireEvent.click(screen.getByLabelText("Select svc-a"));
    fireEvent.click(screen.getByLabelText("Select svc-b"));
    selectBulkTool("trivy");
    fireEvent.click(screen.getByRole("button", { name: "Scan Selected" }));

    await flushDispatch(2);

    const banner = screen.getByRole("alert");
    expect(banner.getAttribute("aria-live")).toBe("assertive");
    expect(banner.textContent).toContain("Scans dispatched");
    expect(banner.textContent).toContain("Dispatched 2 scans across 2 targets");
  });

  it("announces a partial dispatch failure distinctly from full success, not as plain text", async () => {
    // Target 1 dispatches cleanly, target 2 hits an error (e.g. rate limit).
    runScan.mockImplementation((targetId: number) =>
      targetId === 1 ? Promise.resolve({ scan_id: 1, status: "running" }) : Promise.reject(new Error("429")),
    );
    const targets = [target({ id: 1, name: "svc-a" }), target({ id: 2, name: "svc-b" })];

    renderWithWorkspace(<ScansList targets={targets} summary={{}} />);

    fireEvent.click(screen.getByLabelText("Select svc-a"));
    fireEvent.click(screen.getByLabelText("Select svc-b"));
    selectBulkTool("trivy");
    fireEvent.click(screen.getByRole("button", { name: "Scan Selected" }));

    await flushDispatch(2);

    const banner = screen.getByRole("alert");
    expect(banner.getAttribute("aria-live")).toBe("assertive");
    expect(banner.textContent).toContain("Some scans could not be dispatched");
    expect(banner.textContent).toContain("Dispatched 1 scan");
    expect(banner.textContent).toContain("1 target hit an error");
    // The old rendering was indistinguishable, muted `<p>` text; the fix must
    // not just relabel that same element.
    expect(banner.tagName).not.toBe("P");
  });

  it("distinguishes a total dispatch failure from a partial one", async () => {
    runScan.mockRejectedValue(new Error("503"));
    const targets = [target({ id: 1, name: "svc-a" }), target({ id: 2, name: "svc-b" })];

    renderWithWorkspace(<ScansList targets={targets} summary={{}} />);

    fireEvent.click(screen.getByLabelText("Select svc-a"));
    fireEvent.click(screen.getByLabelText("Select svc-b"));
    selectBulkTool("trivy");
    fireEvent.click(screen.getByRole("button", { name: "Scan Selected" }));

    await flushDispatch(2);

    const banner = screen.getByRole("alert");
    expect(banner.textContent).toContain("Scan dispatch failed");
    expect(banner.textContent).toContain("2 targets hit an error");
    expect(banner.textContent).toContain("nothing was dispatched");
  });

  it("tells the reader nothing was dispatched, rather than a bare error, when every selection is deactivated", async () => {
    const targets = [target({ id: 1, name: "svc-a", is_active: false })];

    renderWithWorkspace(<ScansList targets={targets} summary={{}} />);

    fireEvent.click(screen.getByLabelText("Select svc-a"));
    fireEvent.click(screen.getByRole("button", { name: "Scan Selected" }));

    const banner = screen.getByRole("alert");
    expect(banner.textContent).toContain("Nothing dispatched");
    expect(banner.textContent).toMatch(/every selected target is deactivated/i);
    expect(runScan).not.toHaveBeenCalled();
  });
});
