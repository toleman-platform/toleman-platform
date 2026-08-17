import { describe, expect, it } from "vitest";
import { asyncReducer, initialAsyncState, toError } from "./async-state";

/**
 * These cover the transitions that were actually getting hand-rolled wrong
 * across the sixteen files this reducer replaces -- out-of-order responses,
 * data blanking on refetch, and loading left stuck after a failure.
 */
describe("asyncReducer", () => {
  it("starts idle with no data", () => {
    const s = initialAsyncState<number[]>();
    expect(s.status).toBe("idle");
    expect(s.data).toBeNull();
  });

  it("treats seeded data as already successful", () => {
    // Server-rendered data handed to a client component should not flash a
    // skeleton on mount.
    const s = initialAsyncState<number[]>([1, 2]);
    expect(s.status).toBe("success");
    expect(s.data).toEqual([1, 2]);
  });

  it("resolves a request", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    expect(s.status).toBe("loading");
    s = asyncReducer(s, { type: "resolve", requestId: 1, data: "ok" });
    expect(s).toMatchObject({ status: "success", data: "ok", error: null, isRefreshing: false });
  });

  it("keeps data visible during a refetch instead of blanking", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "resolve", requestId: 1, data: "first" });
    s = asyncReducer(s, { type: "start", requestId: 2 });

    expect(s.status).toBe("loading");
    expect(s.data).toBe("first"); // still on screen
    expect(s.isRefreshing).toBe(true);
  });

  it("does not mark the first load as a refresh", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    expect(s.isRefreshing).toBe(false);
  });

  it("ignores a stale response that lands after a newer request started", () => {
    // The classic bug: request 1 is slow, request 2 is fast, and 1's response
    // arrives last and overwrites data the user has already moved past.
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "start", requestId: 2 });
    s = asyncReducer(s, { type: "resolve", requestId: 2, data: "newer" });
    s = asyncReducer(s, { type: "resolve", requestId: 1, data: "older" });

    expect(s.data).toBe("newer");
  });

  it("ignores a stale rejection so an old failure cannot break a good state", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "start", requestId: 2 });
    s = asyncReducer(s, { type: "resolve", requestId: 2, data: "good" });
    s = asyncReducer(s, { type: "reject", requestId: 1, error: new Error("stale boom") });

    expect(s.status).toBe("success");
    expect(s.data).toBe("good");
    expect(s.error).toBeNull();
  });

  it("retains previous data when a refetch fails", () => {
    // Stale rows beside an error banner beat an empty screen, and the caller
    // can still distinguish the two.
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "resolve", requestId: 1, data: "cached" });
    s = asyncReducer(s, { type: "start", requestId: 2 });
    s = asyncReducer(s, { type: "reject", requestId: 2, error: new Error("network") });

    expect(s.status).toBe("error");
    expect(s.data).toBe("cached");
    expect(s.error?.message).toBe("network");
  });

  it("clears loading after an error", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "reject", requestId: 1, error: new Error("x") });
    expect(s.status).toBe("error");
    expect(s.isRefreshing).toBe(false);
  });

  it("clears a previous error when a new request starts", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "reject", requestId: 1, error: new Error("x") });
    s = asyncReducer(s, { type: "start", requestId: 2 });
    expect(s.error).toBeNull();
  });

  it("resets to idle", () => {
    let s = initialAsyncState<string>();
    s = asyncReducer(s, { type: "start", requestId: 1 });
    s = asyncReducer(s, { type: "resolve", requestId: 1, data: "x" });
    s = asyncReducer(s, { type: "reset" });
    expect(s).toMatchObject({ status: "idle", data: null, error: null });
  });
});

describe("toError", () => {
  it("passes an Error through unchanged", () => {
    const e = new Error("boom");
    expect(toError(e)).toBe(e);
  });

  it("wraps a thrown string", () => {
    expect(toError("nope").message).toBe("nope");
  });

  it("gives a readable fallback for anything else", () => {
    // A thrown object would otherwise render as "[object Object]" in the UI.
    expect(toError({ code: 500 }).message).toBe("Something went wrong");
  });
});
