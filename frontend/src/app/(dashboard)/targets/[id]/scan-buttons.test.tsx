import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { ScanButtons } from "./scan-buttons";

/**
 * A scan that failed and a scan that worked used to render identically: one
 * `result` string, written by both the completion and the failure callback,
 * printed through the same muted grey paragraph. The failure path then called
 * `setTool(null)`, which unmounted the progress line -- and with it the live
 * region that had just been handed the failure message -- in the same commit
 * that produced it.
 */

const { runScan, getScan, toolAssignments, activeScans } = vi.hoisted(() => ({
  runScan: vi.fn(),
  getScan: vi.fn(),
  toolAssignments: vi.fn(),
  activeScans: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ api: { runScan, getScan, toolAssignments, activeScans } }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }) }));

function scanRow(over: Record<string, unknown> = {}) {
  return {
    scan_id: 5,
    target_id: 1,
    tool: "semgrep",
    branch: "main",
    status: "completed",
    findings_count: 0,
    started_at: "2026-01-01T00:00:00Z",
    completed_at: null,
    error_message: "",
    elapsed_seconds: 12,
    eta_seconds: null,
    health: "healthy",
    health_note: "",
    ...over,
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  toolAssignments.mockResolvedValue([]);
  activeScans.mockResolvedValue({});
});

afterEach(() => {
  vi.useRealTimers();
  runScan.mockReset();
  getScan.mockReset();
  toolAssignments.mockReset();
  activeScans.mockReset();
});

/** Lets the mounted reads (tool assignments, active scans) settle. */
async function settleMount() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

/** Clicks Run semgrep and lets the dispatch, then one poll, land.
 * pollUntilSettled waits a full interval before its first request. */
async function runSemgrep() {
  fireEvent.click(screen.getByRole("button", { name: "Run semgrep" }));
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2000);
  });
}

describe("ScanButtons, a scan that failed", () => {
  it("reports it as an alert naming the tool, not a muted line", async () => {
    runScan.mockResolvedValue({ scan_id: 5, status: "running" });
    getScan.mockResolvedValue(scanRow({ status: "failed", error_message: "clone timed out after 300s" }));

    render(<ScanButtons targetId={1} workspaceId={2} />);
    await settleMount();
    await runSemgrep();

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("semgrep scan failed");
    expect(alert.textContent).toContain("clone timed out after 300s");
    expect(alert.className).toContain("destructive");
    // The words a successful run produces must not be reachable from here.
    expect(screen.queryByText(/findings ingested/)).toBeNull();
  });

  it("leaves the announcement standing instead of unmounting it", async () => {
    runScan.mockResolvedValue({ scan_id: 5, status: "running" });
    getScan.mockResolvedValue(scanRow({ status: "failed", error_message: "clone timed out after 300s" }));

    render(<ScanButtons targetId={1} workspaceId={2} />);
    await settleMount();
    await runSemgrep();

    // The live region was previously removed in the same commit that set its
    // text, so a screen reader had nothing to announce.
    expect(screen.getByRole("status").textContent).toContain("clone timed out after 300s");
    // ...and the buttons still come back, which is why the two were split.
    expect((screen.getByRole("button", { name: "Run semgrep" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("reports a dispatch the API refused the same way", async () => {
    // A rate-limited or unsupported dispatch never produces a scan id, so it
    // never polls; it must still be as loud as a run that failed mid-flight.
    runScan.mockResolvedValue({ error: "rate limited, try again in 60s" });

    render(<ScanButtons targetId={1} workspaceId={2} />);
    await settleMount();
    fireEvent.click(screen.getByRole("button", { name: "Run semgrep" }));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("rate limited, try again in 60s");
    expect(getScan).not.toHaveBeenCalled();
  });
});

describe("ScanButtons, a scan that completed", () => {
  it("reports the finding count with no error treatment at all", async () => {
    runScan.mockResolvedValue({ scan_id: 5, status: "running" });
    getScan.mockResolvedValue(scanRow({ status: "completed", findings_count: 4 }));

    render(<ScanButtons targetId={1} workspaceId={2} />);
    await settleMount();
    await runSemgrep();

    expect(screen.getByText("semgrep: 4 findings ingested")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reports a clean run as a real zero, not as nothing at all", async () => {
    runScan.mockResolvedValue({ scan_id: 5, status: "running" });
    getScan.mockResolvedValue(scanRow({ status: "completed", findings_count: 0 }));

    render(<ScanButtons targetId={1} workspaceId={2} />);
    await settleMount();
    await runSemgrep();

    expect(screen.getByText("semgrep: 0 findings ingested")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
