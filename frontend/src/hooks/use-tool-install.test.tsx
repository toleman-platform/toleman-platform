import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useToolInstall } from "./use-tool-install";

const installTool = vi.hoisted(() => vi.fn());
const getToolInstall = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { installTool, getToolInstall } }));

function run(overrides: Record<string, unknown> = {}) {
  return {
    run_id: 1,
    tool: "semgrep",
    package: "semgrep",
    status: "running",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: null,
    installed_version: "",
    error: "",
    output_tail: "",
    ...overrides,
  };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.useRealTimers();
  installTool.mockReset();
  getToolInstall.mockReset();
});

/** pollUntilSettled waits one interval before its first request. */
async function advanceOnePoll() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(3000);
  });
}

describe("useToolInstall", () => {
  it("starts with nothing in flight", () => {
    const { result } = renderHook(() => useToolInstall());
    expect(result.current.installs).toEqual({});
  });

  it("marks the tool running as soon as it is dispatched", async () => {
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run());
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    expect(result.current.installs.semgrep.status).toBe("running");
  });

  it("reports the installed version on success", async () => {
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(
      run({ status: "completed", installed_version: "1.136.0" }),
    );
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    expect(result.current.installs.semgrep.status).toBe("completed");
    expect(result.current.installs.semgrep.version).toBe("1.136.0");
  });

  it("surfaces the real failure reason rather than a generic one", async () => {
    // "No matching distribution" and "installed but does not run" call for
    // completely different responses from an admin.
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(
      run({ status: "failed", error: "pip exited 1", output_tail: "ERROR: No matching distribution" }),
    );
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    expect(result.current.installs.semgrep.status).toBe("failed");
    expect(result.current.installs.semgrep.error).toBe("pip exited 1");
    expect(result.current.installs.semgrep.output).toContain("No matching distribution");
  });

  it("reports a refused dispatch without polling", async () => {
    // Not admin / rate limited / not installable never produces a run id.
    installTool.mockRejectedValue(new Error("forbidden"));
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });

    expect(result.current.installs.semgrep.status).toBe("failed");
    expect(result.current.installs.semgrep.error).toBe("forbidden");
    expect(getToolInstall).not.toHaveBeenCalled();
  });

  it("tracks several tools at once", async () => {
    // An admin kitting out a fresh deployment starts more than one install
    // before the first finishes; a single in-flight slot would drop one.
    installTool.mockImplementation(async (tool: string) => run({ tool, run_id: tool.length }));
    getToolInstall.mockResolvedValue(run({ status: "running" }));
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
      await result.current.install("checkov");
    });

    expect(result.current.installs.semgrep.status).toBe("running");
    expect(result.current.installs.checkov.status).toBe("running");
  });

  it("notifies the caller when an install settles, so the registry can refresh", async () => {
    // Without this a freshly installed tool keeps rendering as missing until
    // the admin reloads the page.
    const onSettled = vi.fn();
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run({ status: "completed", installed_version: "1.0" }));
    const { result } = renderHook(() => useToolInstall(onSettled));

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    expect(onSettled).toHaveBeenCalled();
  });

  it("does not notify while the install is still running", async () => {
    const onSettled = vi.fn();
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run({ status: "running" }));
    const { result } = renderHook(() => useToolInstall(onSettled));

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    expect(onSettled).not.toHaveBeenCalled();
  });

  it("stops polling once the install settles", async () => {
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run({ status: "completed", installed_version: "1.0" }));
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    const calls = getToolInstall.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    expect(getToolInstall.mock.calls.length).toBe(calls);
  });

  it("stops polling on unmount", async () => {
    // An install can run for minutes; navigating away must not leave a
    // request firing every few seconds for the rest of the session.
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run({ status: "running" }));
    const { result, unmount } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    const calls = getToolInstall.mock.calls.length;
    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    expect(getToolInstall.mock.calls.length).toBe(calls);
  });

  it("clears state on dismiss", async () => {
    installTool.mockResolvedValue(run());
    getToolInstall.mockResolvedValue(run({ status: "failed", error: "boom" }));
    const { result } = renderHook(() => useToolInstall());

    await act(async () => {
      await result.current.install("semgrep");
    });
    await advanceOnePoll();

    act(() => result.current.dismiss("semgrep"));
    expect(result.current.installs.semgrep).toBeUndefined();
  });
});
