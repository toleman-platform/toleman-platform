/**
 * Date and relative time formatting helpers.
 */

/**
 * Returns a coarse, relative-time label (e.g. "Just now", "2h ago", "Yesterday", "5 days ago", "3w ago").
 * Optimized for compact list rows and historical markers without unnecessary second-level granularity.
 *
 * @param isoTimestamp ISO 8601 formatted date string
 */
export function timeAgo(isoTimestamp: string): string {
  const then = new Date(isoTimestamp).getTime();
  if (Number.isNaN(then)) return isoTimestamp;
  const diffMs = Date.now() - then;
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 60) return diffMin <= 1 ? "Just now" : `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay === 1) return "Yesterday";
  if (diffDay < 7) return `${diffDay} days ago`;
  const diffWeek = Math.floor(diffDay / 7);
  if (diffWeek < 5) return `${diffWeek}w ago`;
  return new Date(then).toLocaleDateString();
}

/**
 * Parse a timestamp the API produced.
 *
 * Every datetime column in this schema is naive UTC (see
 * app/core/time.py's `utcnow`), so FastAPI serialises them with no timezone
 * designator: "2026-09-13T10:00:00". `new Date()` reads a bare string like
 * that as **local** time, which silently shifts it by the reader's offset.
 * Appending the Z the value already meant is the fix.
 *
 * Used by `timeUntil` below, where the shift is unmissable: a countdown
 * rendered from a mis-parsed timestamp can read "in 19 hours" for something
 * due in 24, or go negative and claim a future run already happened.
 * `timeAgo` above has the same latent problem and is deliberately left
 * alone here; changing it moves every historical timestamp in the app at
 * once and is its own change, not a side effect of adding scheduling.
 */
export function parseServerTimestamp(isoTimestamp: string): number {
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(isoTimestamp);
  return new Date(hasZone ? isoTimestamp : `${isoTimestamp}Z`).getTime();
}

/**
 * The forward-looking dual of `timeAgo`: "in 12m", "in 6h", "tomorrow",
 * "in 3 days".
 *
 * Returns "now" rather than a negative duration for a moment that has
 * already passed. That is a state a due-but-not-yet-dispatched schedule
 * genuinely sits in for up to one dispatcher tick, and "in -2 minutes" is
 * not a thing to show a person.
 *
 * @param isoTimestamp ISO 8601 formatted date string, as the API returns it
 */
export function timeUntil(isoTimestamp: string): string {
  const then = parseServerTimestamp(isoTimestamp);
  if (Number.isNaN(then)) return isoTimestamp;
  const diffMs = then - Date.now();
  if (diffMs <= 0) return "now";
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "in under a minute";
  if (diffMin < 60) return `in ${diffMin}m`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `in ${diffHr}h`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay === 1) return "tomorrow";
  if (diffDay < 7) return `in ${diffDay} days`;
  const diffWeek = Math.floor(diffDay / 7);
  if (diffWeek < 5) return `in ${diffWeek}w`;
  return new Date(then).toLocaleDateString();
}
