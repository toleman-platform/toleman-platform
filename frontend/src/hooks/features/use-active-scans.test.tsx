import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useActiveScans } from "./use-active-scans";

const activeScansMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: {
    activeScans: activeScansMock,
  },
}));

describe("useActiveScans", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    activeScansMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls active scans on mount and updates state", async () => {
    activeScansMock.mockResolvedValueOnce({
      "1": [{ id: 101, tool: "semgrep", status: "running" }],
    });

    const { result } = renderHook(() => useActiveScans());

    expect(result.current.activeScans).toEqual({});
    expect(result.current.isTargetScanning(1)).toBe(false);

    await act(async () => {
      await Promise.resolve();
    });

    expect(result.current.activeScans).toEqual({
      "1": [{ id: 101, tool: "semgrep", status: "running" }],
    });
    expect(result.current.isTargetScanning(1)).toBe(true);
    expect(result.current.isTargetScanning(2)).toBe(false);
  });

  it("polls every 20s when idle (no active scans)", async () => {
    activeScansMock.mockResolvedValue({});

    renderHook(() => useActiveScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activeScansMock).toHaveBeenCalledTimes(1);

    // Advancing 10s should not trigger another poll
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(activeScansMock).toHaveBeenCalledTimes(1);

    // Advancing past 20s should trigger second poll
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(activeScansMock).toHaveBeenCalledTimes(2);
  });

  it("polls every 3s when active scans are present", async () => {
    activeScansMock.mockResolvedValue({
      "42": [{ id: 202, tool: "gitleaks", status: "running" }],
    });

    const { result } = renderHook(() => useActiveScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activeScansMock).toHaveBeenCalledTimes(1);
    expect(result.current.isTargetScanning(42)).toBe(true);

    // Active cadence is 3s
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(activeScansMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(activeScansMock).toHaveBeenCalledTimes(3);
  });

  it("refresh forces an immediate poll", async () => {
    activeScansMock.mockResolvedValue({});
    const { result } = renderHook(() => useActiveScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activeScansMock).toHaveBeenCalledTimes(1);

    act(() => {
      result.current.refresh();
    });

    await act(async () => {
      await Promise.resolve();
    });
    expect(activeScansMock).toHaveBeenCalledTimes(2);
  });

  it("suppresses polling errors gracefully", async () => {
    activeScansMock.mockRejectedValueOnce(new Error("Network disconnect"));
    const { result } = renderHook(() => useActiveScans());

    await act(async () => {
      await Promise.resolve();
    });

    // Does not throw and maintains safe empty state
    expect(result.current.activeScans).toEqual({});
    expect(result.current.isTargetScanning(1)).toBe(false);
  });

  it("cancels timer and does not update state on unmount", async () => {
    activeScansMock.mockResolvedValue({});
    const { unmount } = renderHook(() => useActiveScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activeScansMock).toHaveBeenCalledTimes(1);

    unmount();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    // No more calls after unmount
    expect(activeScansMock).toHaveBeenCalledTimes(1);
  });
});
