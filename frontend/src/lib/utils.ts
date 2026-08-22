import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Short relative-time label (e.g. "2h ago", "Yesterday", "5 days ago") for
// compact list rows -- used by the AI Analysis "recent analyses" list
// (issue #122). Deliberately coarse (no seconds/minutes granularity below
// 1h) since these are historical markers, not a live countdown.
export function timeAgo(isoTimestamp: string): string {
  const then = new Date(isoTimestamp).getTime()
  if (Number.isNaN(then)) return isoTimestamp
  const diffMs = Date.now() - then
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 60) return diffMin <= 1 ? 'Just now' : `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay === 1) return 'Yesterday'
  if (diffDay < 7) return `${diffDay} days ago`
  const diffWeek = Math.floor(diffDay / 7)
  if (diffWeek < 5) return `${diffWeek}w ago`
  return then ? new Date(then).toLocaleDateString() : isoTimestamp
}

// (#275) Every dynamic value that reaches an <a href> in this app has been
// individually safe so far -- a hardcoded https:// prefix, a server-built
// URL template, our own TOOL_REGISTRY -- but each of those is a constraint
// that lives at the call site, invisible to the next person who copies the
// pattern. Snyk Code flagged two of these as DOM-based XSS; both were false
// positives on inspection, but the underlying shape (an interpolated value
// reaching href) is real, and "safe today because of a local invariant" is
// exactly the kind of thing that stops being true silently.
//
// Rejects anything that isn't http(s) -- javascript:, data:, vbscript:, and
// a bare scheme-relative or malformed value all return undefined rather
// than a live link. undefined (not "#") so a caller's existing
// `{url && <a href={safeHref(url)}>}` pattern degrades to "no link
// rendered" rather than a link to nowhere.
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url, typeof window === "undefined" ? "http://localhost" : window.location.href);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}
