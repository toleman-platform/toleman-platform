import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { proxy } from "./proxy";

// Issue #128: a session cookie being *present* is not the same as the
// session being *valid* (expired, or revoked via token_version bump). These
// tests pin the two behaviors that regressed: (1) an invalid/stale cookie
// must not trip the "already logged in, skip /login" redirect, and (2) an
// invalid/stale cookie on a protected route must redirect to /login instead
// of letting the broken authenticated shell render. A genuinely valid
// session must still get both the protected-route pass-through and the
// /login -> / shortcut, so the legitimate case isn't collateral damage.

const SESSION_COOKIE = "toleman_session";

function makeRequest(path: string, cookieValue?: string): NextRequest {
  const headers: Record<string, string> = {};
  if (cookieValue !== undefined) {
    headers.cookie = `${SESSION_COOKIE}=${cookieValue}`;
  }
  return new NextRequest(new URL(path, "http://localhost:3000"), { headers });
}

describe("proxy (session-aware routing)", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("redirects an unauthenticated request on a protected route to /login", async () => {
    const res = await proxy(makeRequest("/"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:3000/login?next=%2F");
    expect(fetchMock).not.toHaveBeenCalled(); // no cookie at all; no need to hit the backend
  });

  it("preserves the query string in the post-login \"next\" redirect (#385/#393 deep links)", async () => {
    // pr_guardrail_executor.py's "view"/"request ignore" PR-comment links
    // carry target_id/pr_scan_id/ignore_finding as query params (#393); if
    // an unauthenticated visitor's first hit is one of those links, this
    // query string must survive the login round-trip or the page falls
    // back to whichever target happens to be first in their list instead
    // of the one the link was actually for.
    const res = await proxy(makeRequest("/pr-history?target_id=2&ignore_finding=144"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe(
      "http://localhost:3000/login?next=%2Fpr-history%3Ftarget_id%3D2%26ignore_finding%3D144",
    );
  });

  it("does not redirect a request with no cookie on /login itself", async () => {
    const res = await proxy(makeRequest("/login"));
    expect(res.status).not.toBe(307);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects a REVOKED/expired session cookie on a protected route to /login, not the dashboard", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: "session revoked" }), { status: 401 }));
    const res = await proxy(makeRequest("/", "stale-token"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:3000/login?next=%2F");
    // the stale cookie must be cleared so it isn't resent forever
    const setCookie = res.headers.get("set-cookie") || "";
    expect(setCookie).toContain(`${SESSION_COOKIE}=`);
    expect(setCookie.toLowerCase()).toMatch(/expires=|max-age=0/);
  });

  it("does NOT redirect /login -> / for a revoked/invalid session cookie (the core #128 bug)", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: "session revoked" }), { status: 401 }));
    const res = await proxy(makeRequest("/login", "stale-token"));
    expect(res.status).not.toBe(307);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects /login -> / for a genuinely VALID session (must not break the legitimate shortcut)", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 1, email: "admin@toleman.local" }), { status: 200 }));
    const res = await proxy(makeRequest("/login", "good-token"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:3000/");
  });

  it("passes a valid session through on a protected route without redirecting", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 1, email: "admin@toleman.local" }), { status: 200 }));
    const res = await proxy(makeRequest("/", "good-token"));
    expect(res.status).not.toBe(307);
    expect(res.headers.get("location")).toBeNull();
  });

  it("fails closed (redirects to /login) if the backend is unreachable", async () => {
    fetchMock.mockRejectedValue(new Error("connect ECONNREFUSED"));
    const res = await proxy(makeRequest("/", "some-token"));
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:3000/login?next=%2F");
  });
});
