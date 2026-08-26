import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useTabParam } from "./use-tab-param";

const push = vi.fn();
let currentSearch = "";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/admin",
  useSearchParams: () => new URLSearchParams(currentSearch),
}));

beforeEach(() => {
  push.mockReset();
  currentSearch = "";
});

const TABS = ["users", "integrations", "tools"] as const;

describe("useTabParam", () => {
  it("falls back to the default tab when the URL has no tab param", () => {
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    expect(result.current[0]).toBe("users");
  });

  it("reads the current tab from the URL", () => {
    currentSearch = "tab=integrations";
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    expect(result.current[0]).toBe("integrations");
  });

  it("falls back to the default for an unrecognised tab value", () => {
    // A stale/hand-edited/malicious ?tab= must not crash the page or select
    // nothing; it silently resolves to the same safe default as if the
    // param were absent.
    currentSearch = "tab=not-a-real-tab";
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    expect(result.current[0]).toBe("users");
  });

  it("navigates to a URL carrying the new tab when switching to a non-default tab", () => {
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    act(() => result.current[1]("tools"));
    expect(push).toHaveBeenCalledWith("/admin?tab=tools", { scroll: false });
  });

  it("omits the param entirely when switching back to the default tab", () => {
    // The plain, shareable URL (no query string) should be the common
    // case for the default tab, not always carrying ?tab=<default>.
    currentSearch = "tab=integrations";
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    act(() => result.current[1]("users"));
    expect(push).toHaveBeenCalledWith("/admin", { scroll: false });
  });

  it("preserves other existing query params when switching tabs", () => {
    currentSearch = "workspace_id=7";
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    act(() => result.current[1]("tools"));
    const [url] = push.mock.calls[0];
    expect(url).toContain("workspace_id=7");
    expect(url).toContain("tab=tools");
  });

  it("never pushes scroll-to-top; a tab switch should not jump the page", () => {
    const { result } = renderHook(() => useTabParam(TABS, "users"));
    act(() => result.current[1]("tools"));
    const [, options] = push.mock.calls[0];
    expect(options).toEqual({ scroll: false });
  });
});
