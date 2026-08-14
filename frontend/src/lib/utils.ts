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
