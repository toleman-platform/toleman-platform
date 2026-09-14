import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useActivePrScans } from "./use-active-pr-scans";

const activePrScansMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: {
    activePrScans: activePrScansMock,
  },
}));

describe("useActivePrScans", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    activePrScansMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("polls active PR scans on mount and updates state", async () => {
    activePrScansMock.mockResolvedValueOnce({
      "12:45": {
        target_id: 12,
        pr_number: 45,
        scan_id: 88,
        status: "running",
      },
    });

    const { result } = renderHook(() => useActivePrScans());

    expect(result.current.activePrScans).toEqual({});
    expect(result.current.isPrScanning(12, 45)).toBe(false);

    await act(async () => {
      await Promise.resolve();
    });

    expect(result.current.isPrScanning(12, 45)).toBe(true);
    expect(result.current.isPrScanning(12, 46)).toBe(false);
    expect(result.current.isPrScanning(13, 45)).toBe(false);
  });

  it("polls every 20s when idle", async () => {
    activePrScansMock.mockResolvedValue({});

    renderHook(() => useActivePrScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(2);
  });

  it("polls every 3s when active PR scans exist", async () => {
    activePrScansMock.mockResolvedValue({
      "5:101": { target_id: 5, pr_number: 101, scan_id: 99, status: "running" },
    });

    const { result } = renderHook(() => useActivePrScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);
    expect(result.current.isPrScanning(5, 101)).toBe(true);

    // Active cadence is 3s
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(2);
  });

  it("refresh immediately forces a new poll", async () => {
    activePrScansMock.mockResolvedValue({});
    const { result } = renderHook(() => useActivePrScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);

    act(() => {
      result.current.refresh();
    });

    await act(async () => {
      await Promise.resolve();
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(2);
  });

  it("suppresses polling errors cleanly", async () => {
    activePrScansMock.mockRejectedValueOnce(new Error("Server error"));
    const { result } = renderHook(() => useActivePrScans());

    await act(async () => {
      await Promise.resolve();
    });

    expect(result.current.activePrScans).toEqual({});
    expect(result.current.isPrScanning(1, 1)).toBe(false);
  });

  it("stops polling on unmount", async () => {
    activePrScansMock.mockResolvedValue({});
    const { unmount } = renderHook(() => useActivePrScans());

    await act(async () => {
      await Promise.resolve();
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);

    unmount();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    expect(activePrScansMock).toHaveBeenCalledTimes(1);
  });
});
