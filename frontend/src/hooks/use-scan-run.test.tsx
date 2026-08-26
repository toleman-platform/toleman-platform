import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useScanRun } from "./use-scan-run";

const getScan = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { getScan } }));

function run(overrides: Record<string, unknown> = {}) {
  return {
    scan_id: 1,
    target_id: 1,
    tool: "semgrep",
    branch: "main",
    status: "running",
    findings_count: 0,
    started_at: "2026-01-01T00:00:00Z",
    completed_at: null,
    error_message: "",
    elapsed_seconds: 4,
    eta_seconds: null,
    ...overrides,
  };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.useRealTimers();
  getScan.mockReset();
});

/** pollUntilSettled waits one interval before its first request. */
async function advanceOnePoll() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2000);
  });
}

describe("useScanRun", () => {
  it("starts with no phase at all", () => {
    const { result } = renderHook(() => useScanRun());
    expect(result.current.phase).toBeNull();
  });

  it("reports queued before the first poll returns", () => {
    // The gap between the API accepting a dispatch and a worker picking it
    // up is real; calling it "running" would claim work had begun.
    getScan.mockResolvedValue(run());
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    expect(result.current.phase).toBe("queued");
  });

  it("moves to running once the server confirms it", async () => {
    getScan.mockResolvedValue(run());
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();
    expect(result.current.phase).toBe("running");
  });

  it("passes through an ETA the server grounded in history", async () => {
    getScan.mockResolvedValue(run({ eta_seconds: 40, elapsed_seconds: 10 }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();
    expect(result.current.etaSeconds).toBe(40);
  });

  it("keeps the ETA null when the server had too little history", async () => {
    getScan.mockResolvedValue(run({ eta_seconds: null }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();
    // Null must survive the whole way to the UI, no default substituted
    // anywhere in between.
    expect(result.current.etaSeconds).toBeNull();
  });

  it("ticks elapsed time forward between polls", async () => {
    getScan.mockResolvedValue(run({ elapsed_seconds: 10 }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();
    expect(result.current.elapsedSeconds).toBe(10);

    // No new poll, but the stopwatch should still advance; otherwise the
    // number visibly freezes between requests. The exact value depends on
    // how many timer ticks land, so this asserts movement past the server's
    // last word rather than a specific count.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(result.current.elapsedSeconds).toBeGreaterThan(10);
  });

  it("fires onCompleted with the findings count", async () => {
    const onCompleted = vi.fn();
    getScan.mockResolvedValue(run({ status: "completed", findings_count: 7, elapsed_seconds: 33 }));
    const { result } = renderHook(() => useScanRun({ onCompleted }));
    act(() => result.current.track(1));
    await advanceOnePoll();

    expect(result.current.phase).toBe("completed");
    expect(onCompleted).toHaveBeenCalledWith(7);
  });

  it("drops the ETA once the scan settles", async () => {
    getScan.mockResolvedValue(run({ status: "completed", eta_seconds: 40 }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();
    // It has a real duration now; an estimate for it would be noise.
    expect(result.current.etaSeconds).toBeNull();
  });

  it("freezes elapsed time at completion", async () => {
    getScan.mockResolvedValue(run({ status: "completed", elapsed_seconds: 33 }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(result.current.elapsedSeconds).toBe(33);
  });

  it("surfaces the real failure reason, not a generic one", async () => {
    const onFailed = vi.fn();
    getScan.mockResolvedValue(
      run({ status: "failed", error_message: "Timed out: no update received within 30 minutes" }),
    );
    const { result } = renderHook(() => useScanRun({ onFailed }));
    act(() => result.current.track(1));
    await advanceOnePoll();

    expect(result.current.phase).toBe("failed");
    expect(result.current.error).toContain("Timed out");
    expect(onFailed).toHaveBeenCalledWith(expect.stringContaining("Timed out"));
  });

  it("stops polling a scan that does not exist", async () => {
    // The API answers a missing row with { error }. Left unhandled, the loop
    // would poll a nonexistent scan until its timeout.
    getScan.mockResolvedValue({ error: "scan not found" });
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    expect(result.current.phase).toBe("failed");
    const callsAfterSettle = getScan.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(getScan.mock.calls.length).toBe(callsAfterSettle);
  });

  it("stops polling once the scan completes", async () => {
    getScan.mockResolvedValue(run({ status: "completed" }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    const calls = getScan.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(getScan.mock.calls.length).toBe(calls);
  });

  it("stops polling on unmount", async () => {
    // A user who navigates away mid-scan must not leave a request firing
    // every two seconds for the rest of the session.
    getScan.mockResolvedValue(run());
    const { result, unmount } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    const calls = getScan.mock.calls.length;
    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(getScan.mock.calls.length).toBe(calls);
  });

  it("reports a dispatch that never produced a scan id", async () => {
    const onFailed = vi.fn();
    const { result } = renderHook(() => useScanRun({ onFailed }));
    act(() => result.current.fail("rate limit exceeded"));
    expect(result.current.phase).toBe("failed");
    expect(result.current.error).toBe("rate limit exceeded");
    expect(onFailed).toHaveBeenCalledWith("rate limit exceeded");
    expect(getScan).not.toHaveBeenCalled();
  });

  it("clears everything on reset", async () => {
    getScan.mockResolvedValue(run({ status: "failed", error_message: "boom" }));
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    act(() => result.current.reset());
    expect(result.current.phase).toBeNull();
    expect(result.current.error).toBeNull();
    expect(result.current.elapsedSeconds).toBe(0);
  });

  it("abandons the previous scan when a new one is tracked", async () => {
    getScan.mockResolvedValue(run());
    const { result } = renderHook(() => useScanRun());
    act(() => result.current.track(1));
    await advanceOnePoll();

    act(() => result.current.track(2));
    getScan.mockClear();
    await advanceOnePoll();
    await advanceOnePoll();

    // Only the newest scan is polled; the old loop was cancelled rather than
    // left running alongside it.
    expect(getScan).toHaveBeenCalledWith(2);
    expect(getScan.mock.calls.every(([id]) => id === 2)).toBe(true);
  });
});
