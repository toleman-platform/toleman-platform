/**
 * Shared active-workspace cookie constant/parser for Server Components and
 * WorkspaceContext. Keep this module free of use-client so server fetches can read the
 * same selection without importing client references.
 */

export const WORKSPACE_COOKIE_KEY = "toleman-active-workspace";
const ALL_WORKSPACES_SENTINEL = "all";

/**
 * Parse cookie scope: undefined means missing/unreliable and callers use accessible
 * defaults; null explicitly means all workspaces. WorkspaceContext validates stored IDs
 * and corrects the cookie on load. Until then, a stale ID may return a retryable
 * authorization error.
 */
export function parseWorkspaceCookie(raw: string | undefined): number | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === ALL_WORKSPACES_SENTINEL) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : undefined;
}
