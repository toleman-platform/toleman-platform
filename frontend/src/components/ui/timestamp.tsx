"use client";

import * as React from "react";
import {
  formatUtcDate,
  formatUtcDateTime,
  formatUtcTime,
  parseServerTimestamp,
  timeAgo,
} from "@/lib/format/date";

export type TimestampMode = "datetime" | "date" | "time" | "relative";

export interface TimestampProps {
  /**
   * A timestamp as the API sends it. Naive UTC ("2026-09-13T10:00:00") is
   * read as the UTC it means, via `parseServerTimestamp`.
   */
  value: string | null | undefined;
  /** How much of the instant to show. Defaults to date and time. */
  mode?: TimestampMode;
  /**
   * What to show when there is no timestamp at all. An absent timestamp is
   * an absence, never an epoch or a zero, so each surface passes the wording
   * it already uses for the unknown case ("never used", "—").
   */
  fallback?: React.ReactNode;
  className?: string;
}

// Nothing in this "store" ever changes, so the only transition React reports
// is the one from the server snapshot to the client snapshot -- which
// happens exactly once, immediately after hydration. Declared at module
// scope so the subscribe identity is stable and React does not resubscribe
// on every render.
const neverChanges = () => () => {};

/**
 * `false` while rendering on the server and through the hydration pass,
 * `true` from the first client commit onwards.
 *
 * Deliberately not `useState(false)` plus `useEffect(() => setMounted(true),
 * [])`: that derives state inside an effect, and it also runs the
 * pre-hydration branch on client-only renders where there was never a server
 * render to match. `useSyncExternalStore` is the API React provides for
 * exactly this question -- it hands the *server* snapshot to the hydration
 * render so the markup matches byte for byte, then re-renders with the
 * client snapshot in the pass it already schedules.
 */
function useIsHydrated(): boolean {
  return React.useSyncExternalStore(
    neverChanges,
    () => true,
    () => false
  );
}

/** The server-stable text: same bytes on any machine, in any timezone. */
function stableText(value: string, mode: TimestampMode): string {
  if (mode === "date") return formatUtcDate(value);
  if (mode === "time") return formatUtcTime(value);
  // A relative label is read off the clock, so it has no server-stable form
  // at all -- the server's "3h ago" and the browser's are two different
  // measurements. The absolute value stands in until the viewer's own clock
  // is the one being read.
  return formatUtcDateTime(value);
}

/** The text once the viewer's own locale, timezone and clock are available. */
function viewerText(date: Date, value: string, mode: TimestampMode): string {
  if (mode === "date") return date.toLocaleDateString();
  if (mode === "time") return date.toLocaleTimeString();
  if (mode === "relative") return timeAgo(value);
  return date.toLocaleString();
}

/**
 * The full absolute time, for the `title`. Carries the UTC value alongside
 * the viewer's own rendering rather than instead of it: a relative or
 * date-only rendering must never be the only thing that says when an event
 * happened, and "which timezone was that in" is not a question an audit
 * trail should leave open.
 */
function absoluteLabel(date: Date, value: string, isHydrated: boolean): string {
  const utc = formatUtcDateTime(value);
  return isHydrated ? `${date.toLocaleString()} (${utc})` : utc;
}

/**
 * Renders an API timestamp without a hydration mismatch.
 *
 * The server and the hydration render both emit the locale-independent UTC
 * form; once mounted, the component re-renders with the viewer's own
 * formatting. The machine-readable instant is always present in
 * `<time dateTime>`, and the full absolute time is always in `title`, so
 * neither the brief pre-hydration state nor a relative label ("3h ago")
 * hides the exact moment an event occurred.
 */
export function Timestamp({
  value,
  mode = "datetime",
  fallback = "—",
  className,
}: TimestampProps) {
  const isHydrated = useIsHydrated();

  if (value === null || value === undefined || value === "") {
    return <span className={className}>{fallback}</span>;
  }

  const ms = parseServerTimestamp(value);
  if (Number.isNaN(ms)) {
    // Present but unparseable. Show what the API actually sent rather than
    // "Invalid Date" or a confident epoch, and emit no `<time>`: there is no
    // machine-readable instant to put in one.
    return <span className={className}>{value}</span>;
  }

  const date = new Date(ms);

  return (
    <time
      dateTime={date.toISOString()}
      title={absoluteLabel(date, value, isHydrated)}
      className={className}
    >
      {isHydrated ? viewerText(date, value, mode) : stableText(value, mode)}
    </time>
  );
}

/**
 * The same absolute label `<Timestamp>` puts in its `title`, as a string.
 *
 * For the few places that need a `title` on an element which is not itself
 * the timestamp -- an age in days, an SLA countdown -- and so cannot hold a
 * nested `<time>`. Those attributes are part of the server-rendered HTML
 * too, so a bare `toLocaleString()` in one mismatches on hydration exactly
 * as a rendered one does.
 */
export function useAbsoluteTimestamp(value: string): string {
  const isHydrated = useIsHydrated();
  const ms = parseServerTimestamp(value);
  if (Number.isNaN(ms)) return value;
  return absoluteLabel(new Date(ms), value, isHydrated);
}
