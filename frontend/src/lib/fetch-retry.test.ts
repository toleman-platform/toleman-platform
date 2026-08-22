import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fetchWithConnectionRetry } from "./api";

// (#235, UI-03) The retry that absorbs a backend restart's few seconds of
// connection-refused before it becomes a NetworkError and, upstream of
// that, a blank page. Tested directly against a mocked global fetch so the
// retry count and backoff behavior are pinned precisely, independent of
// jsonFetch's own request-building logic.

describe("fetchWithConnectionRetry", () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    vi.useFakeTimers();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.useRealTimers();
  });

  it("returns immediately on a successful first attempt, no delay", async () => {
    const response = new Response("ok");
    const fetchMock = vi.fn().mockResolvedValue(response);
    global.fetch = fetchMock;

    const result = await fetchWithConnectionRetry("http://x", {});
    expect(result).toBe(response);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries after a connection failure and succeeds on the second attempt", async () => {
    const response = new Response("ok");
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValueOnce(response);
    global.fetch = fetchMock;

    const promise = fetchWithConnectionRetry("http://x", {});
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result).toBe(response);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("succeeds on the third attempt after two failures", async () => {
    const response = new Response("ok");
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockRejectedValueOnce(new TypeError("fetch failed"))
      .mockResolvedValueOnce(response);
    global.fetch = fetchMock;

    const promise = fetchWithConnectionRetry("http://x", {});
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result).toBe(response);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("throws the last error once every attempt is exhausted, without retrying forever", async () => {
    const finalError = new TypeError("still down");
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("first"))
      .mockRejectedValueOnce(new TypeError("second"))
      .mockRejectedValueOnce(finalError);
    global.fetch = fetchMock;

    const promise = fetchWithConnectionRetry("http://x", {}).catch((e) => e);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result).toBe(finalError);
    // Exactly 3 attempts -- confirms this does not silently keep retrying
    // beyond the bounded backoff, which would turn a real outage into an
    // even-longer hang on every page render.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("never retries an HTTP error response -- only a fetch() throw", async () => {
    // A 500 is a real response from a server that is up. Retrying it here
    // would just be a slower version of the same failure, and could
    // duplicate a non-idempotent write if this were ever reused for a
    // path that doesn't already guarantee the request never reached the
    // server. fetchWithConnectionRetry only sees fetch() *throwing* -- an
    // ok-or-not Response is never something it decides to retry.
    const errorResponse = new Response("server error", { status: 500 });
    const fetchMock = vi.fn().mockResolvedValue(errorResponse);
    global.fetch = fetchMock;

    const result = await fetchWithConnectionRetry("http://x", {});
    expect(result).toBe(errorResponse);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
