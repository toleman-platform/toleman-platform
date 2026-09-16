/**
 * Active-workspace cookie constant + parser, shared by Server Components and
 * the client-side WorkspaceContext (issue #506).
 *
 * Deliberately a plain module without `"use client"`, same reasoning as
 * tokens/theme.ts: a page.tsx Server Component (Dashboard, Findings,
 * Targets, Scans -- the pages that fetch data server-side via `next/headers`
 * `cookies()`) needs to read the caller's active workspace to pass
 * `workspace_id` into its own server-side `api.*()` calls, and importing a
 * constant from a `"use client"` file would pull a client reference into the
 * server bundle. WorkspaceContext (the client side, which owns writing this
 * cookie) imports and re-exports this same constant rather than redeclaring
 * it, so the two can never drift.
 */

export const WORKSPACE_COOKIE_KEY = "toleman-active-workspace";
const ALL_WORKSPACES_SENTINEL = "all";

/**
 * Parses the raw cookie value a Server Component reads via `cookies()`.
 * `undefined` (no cookie, or an unparseable one) means no reliable signal --
 * callers should fall back to their own unfiltered/accessible-scope default,
 * same as `workspace_id` being omitted from the request entirely. `null`
 * means "All workspaces" was explicitly chosen. A stale id (a workspace the
 * cookie's owner no longer belongs to, e.g. after being removed from it) is
 * not distinguished here -- the client-side WorkspaceContext is what
 * validates against the real list and corrects the cookie on next load; a
 * server-rendered page passing a since-invalid id simply gets the same 403
 * `narrow_workspace_scope` already gives any other caller, which existing
 * `settleOrNull`-wrapped fetches on these pages already render as a
 * retryable error rather than crashing the page.
 */
export function parseWorkspaceCookie(raw: string | undefined): number | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === ALL_WORKSPACES_SENTINEL) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : undefined;
}
