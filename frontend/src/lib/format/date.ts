/**
 * Date and relative time formatting helpers.
 */

/**
 * Returns a coarse, relative-time label (e.g. "Just now", "2h ago", "Yesterday", "5 days ago", "3w ago").
 * Optimized for compact list rows and historical markers without unnecessary second-level granularity.
 *
 * Parses through `parseServerTimestamp`, so a bare API timestamp is read as
 * the UTC it already meant rather than as the reader's local time (#443).
 * Before that, every relative label in the app was wrong by the reader's
 * offset -- and wrong in the direction that matters: east of UTC a scan
 * that had just finished read as hours old, while west of UTC the age went
 * negative and fell into the `diffMin <= 1` branch, so something genuinely
 * hours stale rendered as "Just now". A staleness indicator that reports
 * stale things as fresh is worse than not having one.
 *
 * @param isoTimestamp ISO 8601 formatted date string
 */
export function timeAgo(isoTimestamp: string): string {
  const then = parseServerTimestamp(isoTimestamp);
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
  // Past five weeks the relative form stops being useful and this falls back
  // to a date. That fallback must stay locale-independent for the same reason
  // formatUtcDateTime exists: the server and the browser disagree about both
  // locale and timezone, and a date is exactly where that disagreement shows.
  return formatUtcDate(new Date(then).toISOString());
}

/**
 * Parse API timestamps as UTC: naive datetime strings need Z because JavaScript
 * otherwise interprets them as local time. Use this for relative timestamps and
 * countdowns so client timezone offsets cannot shift the represented instant.
 */
export function parseServerTimestamp(isoTimestamp: string): number {
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(isoTimestamp);
  return new Date(hasZone ? isoTimestamp : `${isoTimestamp}Z`).getTime();
}

/**
 * `parseServerTimestamp` as a `Date`, for the many call sites that want
 * `.toLocaleString()` / `.toLocaleDateString()` rather than arithmetic.
 *
 * Exists so those sites do not each write `new Date(parseServerTimestamp(x))`
 * -- and, more to the point, so the obvious thing to reach for when
 * rendering an API timestamp is the correct one. The bug this file is about
 * came from `new Date(iso)` being the obvious thing everywhere.
 *
 * An invalid input yields an Invalid Date, exactly as `new Date` would, so
 * existing `Number.isNaN(d.getTime())` guards keep working unchanged.
 */
export function serverDate(isoTimestamp: string): Date {
  return new Date(parseServerTimestamp(isoTimestamp));
}

/**
 * "since Mar 4" -- the shared implementation behind the SBOM and API
 * Discovery "new since last run" badges, which had identical private copies
 * of this. Falls back to the raw string on an unparseable value rather than
 * rendering "Invalid Date".
 */
const UTC_MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
] as const;

export function formatSince(isoTimestamp: string): string {
  const d = serverDate(isoTimestamp);
  if (Number.isNaN(d.getTime())) return isoTimestamp;
  // Locale-independent for the same reason: this string is server-rendered on
  // the SBOM and API-discovery pages, so a month name chosen by the Node
  // process's locale is a value the browser then disagrees with.
  return `since ${UTC_MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
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
  return formatUtcDate(new Date(then).toISOString());
}

/**
 * Deterministic UTC date/time strings keep SSR and hydration independent of host
 * locale/timezone. Timestamp upgrades them to viewer-local formatting after mount. Echo
 * unparseable input unchanged rather than displaying Invalid Date or epoch.
 */
export function formatUtcDateTime(isoTimestamp: string): string {
  const d = utcDateOrNull(isoTimestamp);
  if (d === null) return isoTimestamp;
  return `${utcDatePart(d)} ${utcTimePart(d)} UTC`;
}

/** Date half of {@link formatUtcDateTime}: "2026-09-13 UTC". */
export function formatUtcDate(isoTimestamp: string): string {
  const d = utcDateOrNull(isoTimestamp);
  if (d === null) return isoTimestamp;
  return `${utcDatePart(d)} UTC`;
}

/** Time half of {@link formatUtcDateTime}: "10:00:00 UTC". */
export function formatUtcTime(isoTimestamp: string): string {
  const d = utcDateOrNull(isoTimestamp);
  if (d === null) return isoTimestamp;
  return `${utcTimePart(d)} UTC`;
}

function utcDateOrNull(isoTimestamp: string): Date | null {
  const ms = parseServerTimestamp(isoTimestamp);
  return Number.isNaN(ms) ? null : new Date(ms);
}

function utcDatePart(d: Date): string {
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

function utcTimePart(d: Date): string {
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}
