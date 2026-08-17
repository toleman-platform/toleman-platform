import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useDebouncedValue } from "./use-debounced-value";

describe("useDebouncedValue", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("returns the initial value immediately", () => {
    const { result } = renderHook(() => useDebouncedValue("sql", 200));
    expect(result.current).toBe("sql");
  });

  it("does not update before the delay elapses", () => {
    const { rerender, result } = renderHook(({ v }) => useDebouncedValue(v, 200), {
      initialProps: { v: "s" },
    });
    rerender({ v: "sq" });
    act(() => void vi.advanceTimersByTime(199));
    expect(result.current).toBe("s");
  });

  it("updates once the delay elapses", () => {
    const { rerender, result } = renderHook(({ v }) => useDebouncedValue(v, 200), {
      initialProps: { v: "s" },
    });
    rerender({ v: "sq" });
    act(() => void vi.advanceTimersByTime(200));
    expect(result.current).toBe("sq");
  });

  it("emits only the final value of a fast burst", () => {
    // This is the whole point: typing "sqli" should produce one search, not
    // four, and the one it produces must be for the full string.
    const { rerender, result } = renderHook(({ v }) => useDebouncedValue(v, 200), {
      initialProps: { v: "s" },
    });
    for (const v of ["sq", "sql", "sqli"]) {
      rerender({ v });
      act(() => void vi.advanceTimersByTime(50));
    }
    expect(result.current).toBe("s");

    act(() => void vi.advanceTimersByTime(200));
    expect(result.current).toBe("sqli");
  });

  it("debounces a value going back to empty too", () => {
    // Clearing the box must also settle, otherwise the last query would stay
    // pending forever behind an empty input.
    const { rerender, result } = renderHook(({ v }) => useDebouncedValue(v, 200), {
      initialProps: { v: "sqli" },
    });
    rerender({ v: "" });
    act(() => void vi.advanceTimersByTime(200));
    expect(result.current).toBe("");
  });

  it("cancels the pending update on unmount", () => {
    const { rerender, unmount } = renderHook(({ v }) => useDebouncedValue(v, 200), {
      initialProps: { v: "a" },
    });
    rerender({ v: "b" });
    unmount();
    // No state update should be attempted after unmount; advancing the clock
    // must not throw or warn.
    expect(() => act(() => void vi.advanceTimersByTime(500))).not.toThrow();
  });
});
