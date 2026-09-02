/**
 * Core HTTP client and transport infrastructure.
 *
 * Handles base URL resolution for both browser and Node.js Server Component environments,
 * session cookie forwarding during server-side rendering, connection failure retries,
 * and standard API error wrapping.
 */

import { sleep } from "@/std-lib";

export const DEFAULT_API_URL = "http://localhost:8000";

declare global {
  interface Window {
    __TOLEMAN_API_URL__?: string;
  }
}

/**
 * Resolves the backend API URL dynamically based on runtime execution context.
 *
 * Precedence:
 * 1. Server-side: API_INTERNAL_URL (Docker network) -> NEXT_PUBLIC_API_URL -> DEFAULT_API_URL
 * 2. Browser: window.__TOLEMAN_API_URL__ (injected runtime config) -> NEXT_PUBLIC_API_URL -> DEFAULT_API_URL
 */
export function apiBaseUrl(): string {
  if (typeof window === "undefined") {
    return process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;
  }
  return window.__TOLEMAN_API_URL__ || process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;
}

/**
 * Carries the HTTP response status code alongside the error message.
 * Enables consumers to distinguish between auth revocation (401), not found (404),
 * and general server errors.
 */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * Error thrown when a network request never reaches the backend
 * (e.g. connection refused, DNS failure, or CORS preflight rejection).
 * Deliberately does NOT subclass ApiError since no HTTP status code exists.
 */
export class NetworkError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "NetworkError";
    this.cause = cause;
  }
}

const NETWORK_RETRY_DELAYS_MS = [150, 300];
export const NETWORK_RETRY_ATTEMPTS = NETWORK_RETRY_DELAYS_MS.length + 1;

/**
 * Executes a fetch call with retry logic on connection errors.
 * Absorbs transient container restart windows (~450ms max backoff)
 * to prevent blank-screen rendering errors in Server Components.
 */
export async function fetchWithConnectionRetry(url: string, init: RequestInit): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < NETWORK_RETRY_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      await sleep(NETWORK_RETRY_DELAYS_MS[attempt - 1]);
    }
    try {
      return await fetch(url, init);
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

/**
 * Authenticated JSON fetch helper.
 * Automatically forwards `toleman_session` cookies during Server Component rendering
 * and unpacks FastAPI error details.
 *
 * @param path API path relative to base URL (e.g. "/api/targets")
 * @param init Standard RequestInit options
 */
export async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };

  // Server Components run on the server where credentials: "include" has no browser cookie jar.
  // Explicitly forward the session cookie so server-rendered pages pass authentication.
  if (typeof window === "undefined") {
    const { cookies } = await import("next/headers");
    const cookieStore = await cookies();
    const session = cookieStore.get("toleman_session");
    if (session) {
      headers["Cookie"] = `toleman_session=${session.value}`;
    }
  }

  let res: Response;
  try {
    res = await fetchWithConnectionRetry(`${apiBaseUrl()}${path}`, {
      ...init,
      cache: "no-store",
      credentials: "include",
      headers,
    });
  } catch (e) {
    throw new NetworkError(
      `Could not reach the API at ${apiBaseUrl()}. The request never arrived after ${NETWORK_RETRY_ATTEMPTS} attempts; check that the backend is running and that this origin is allowed by PUBLIC_BASE_URL/EXTRA_CORS_ORIGINS.`,
      e,
    );
  }

  if (!res.ok) {
    let detail: string | undefined;
    try {
      const body = await res.json();
      if (body && typeof body.detail === "string") detail = body.detail;
    } catch {
      // Body wasn't JSON, fall through to generic message
    }
    throw new ApiError(detail || `API ${path} failed: ${res.status}`, res.status);
  }

  return res.json();
}
