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
  return then ? new Date(then).toLocaleDateString() : isoTimestamp;
}
