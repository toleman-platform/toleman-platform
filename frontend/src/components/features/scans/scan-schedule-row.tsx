"use client";

import { Radar, ShieldCheck } from "lucide-react";
import type { ScanScheduleType, ScanScheduleView } from "@/lib/api";
import { timeAgo, timeUntil } from "@/lib/format/date";

// One editable schedule (issue #306), shared by the per-target panel on the
// target detail page and the workspace defaults in Control Plane. The two
// scopes differ only in what "Inherit" means and in which level sits above
// them, so they are one component with a `scope` prop rather than two that
// drift apart the first time the wording changes.
//
// The container owns fetching and persistence; this renders state and calls
// back. That keeps the optimistic-update and error handling in one place per
// page instead of once per row.

export type ScanScheduleScope = "target" | "workspace";

const SCAN_TYPE_META: Record<
  ScanScheduleType,
  { label: string; description: string; icon: typeof ShieldCheck }
> = {
  full_scan: {
    label: "Full scan",
    description:
      "Every scanner this workspace has enabled for on-demand scanning, against the default branch. Keeps the PR Guardrail baseline and posture pages from going stale between manual runs.",
    icon: ShieldCheck,
  },
  api_scan: {
    label: "Active API scan",
    description:
      "Probes the endpoints already discovered for this target, at the API base URL its owner configured. Never an inferred host.",
    icon: Radar,
  },
};

// Deliberately a short list of sane cadences rather than a free-text number
// of hours. The backend accepts any value from 1 hour up, but a scan is an
// expensive, network-visible thing and the useful choices are few; an open
// number field mostly invites someone to type 2 and quietly saturate the
// scan queue for every target in the workspace (#229).
const INTERVAL_CHOICES: { hours: number; label: string }[] = [
  { hours: 6, label: "Every 6 hours" },
  { hours: 12, label: "Every 12 hours" },
  { hours: 24, label: "Every 24 hours" },
  { hours: 72, label: "Every 3 days" },
  { hours: 168, label: "Weekly" },
];

function sourceLabel(source: ScanScheduleView["enabled_source"]): string {
  if (source === "target") return "set on this target";
  if (source === "workspace") return "inherited from the workspace default";
  return "the built-in default";
}

function intervalLabel(hours: number): string {
  const known = INTERVAL_CHOICES.find((c) => c.hours === hours);
  if (known) return known.label.toLowerCase();
  return `every ${hours}h`;
}

export function ScanScheduleRow({
  view,
  scope,
  busy,
  disabledReason,
  onChange,
  onReset,
}: {
  view: ScanScheduleView;
  scope: ScanScheduleScope;
  busy: boolean;
  /**
   * Why this schedule will dispatch nothing even though it looks armed
   * (e.g. the target has no API base URL). Rendered as a warning next to
   * the controls; a schedule that cannot fire must say so rather than
   * presenting as healthy.
   */
  disabledReason?: string | null;
  onChange: (patch: { enabled?: boolean | null; interval_hours?: number | null }) => void;
  onReset?: () => void;
}) {
  const meta = SCAN_TYPE_META[view.scan_type];
  const Icon = meta.icon;
  // Only offer the reset when there is actually an override to drop;
  // a row that already inherits everything has nothing to reset to.
  const hasOverride = view.override_enabled !== null || view.override_interval_hours !== null;

  // "Inherit" is a real, distinct option, not a synonym for the value it
  // currently resolves to: picking it means "follow whatever the level above
  // decides, including if that changes later".
  const stateValue = view.override_enabled === null ? "inherit" : view.override_enabled ? "on" : "off";
  const intervalValue = view.override_interval_hours === null ? "inherit" : String(view.override_interval_hours);

  return (
    <div className="flex flex-col gap-3 px-4 py-4">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">{meta.label}</div>
          <p className="mt-0.5 text-xs text-muted-foreground">{meta.description}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 pl-11">
        <label className="sr-only" htmlFor={`sched-state-${scope}-${view.scan_type}`}>
          {meta.label} schedule state
        </label>
        <select
          id={`sched-state-${scope}-${view.scan_type}`}
          className="h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground"
          value={stateValue}
          disabled={busy}
          onChange={(e) =>
            onChange({ enabled: e.target.value === "inherit" ? null : e.target.value === "on" })
          }
        >
          <option value="inherit">
            {scope === "target" ? "Inherit from workspace" : "Use built-in default"}
          </option>
          <option value="on">Scheduled</option>
          <option value="off">Paused</option>
        </select>

        <label className="sr-only" htmlFor={`sched-interval-${scope}-${view.scan_type}`}>
          {meta.label} cadence
        </label>
        <select
          id={`sched-interval-${scope}-${view.scan_type}`}
          className="h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground"
          value={intervalValue}
          disabled={busy}
          onChange={(e) =>
            onChange({
              interval_hours: e.target.value === "inherit" ? null : Number(e.target.value),
            })
          }
        >
          <option value="inherit">
            {scope === "target" ? "Inherit cadence" : "Default cadence"}
          </option>
          {INTERVAL_CHOICES.map((c) => (
            <option key={c.hours} value={c.hours}>
              {c.label}
            </option>
          ))}
          {/* A stored cadence this list does not offer (set via the API, or
              left over from an older list) must still render as itself
              rather than silently snapping the select to something the
              operator never chose. */}
          {view.override_interval_hours !== null &&
            !INTERVAL_CHOICES.some((c) => c.hours === view.override_interval_hours) && (
              <option value={view.override_interval_hours}>
                Every {view.override_interval_hours}h
              </option>
            )}
        </select>

        {scope === "target" && onReset && hasOverride && (
          <button
            type="button"
            onClick={onReset}
            disabled={busy}
            className="text-xs text-muted-foreground underline-offset-2 transition-colors hover:text-foreground hover:underline"
          >
            Reset to workspace default
          </button>
        )}
      </div>

      <div className="flex flex-col gap-1 pl-11 text-xs">
        <p className="text-muted-foreground">
          {view.enabled ? (
            <>
              Runs {intervalLabel(view.interval_hours)} ({sourceLabel(view.interval_source)}).
            </>
          ) : (
            <>Paused ({sourceLabel(view.enabled_source)}); nothing is scheduled.</>
          )}
        </p>

        {/* Unknown vs zero vs empty. A schedule that has never fired says so
            in words: rendering nothing here would make a scheduler that is
            not running look identical to one that simply has not come round
            yet, which is the exact failure this panel exists to make
            visible. */}
        <p className="text-muted-foreground">
          {view.last_run_at === null ? (
            <span className="text-muted-foreground">
              Last run: never — this schedule has not fired yet
            </span>
          ) : (
            <>
              Last run: {timeAgo(view.last_run_at)}
              {view.last_dispatched_count !== null && (
                <>
                  {" · "}
                  {view.last_dispatched_count === 0
                    ? "dispatched nothing"
                    : `dispatched ${view.last_dispatched_count} scan${view.last_dispatched_count === 1 ? "" : "s"}`}
                </>
              )}
            </>
          )}
        </p>

        <p className="text-muted-foreground">
          {!view.enabled
            ? "Next run: —"
            : view.next_run_at === null
              ? "Next run: on the scheduler's next pass"
              : `Next run: ${timeUntil(view.next_run_at)}`}
        </p>

        {disabledReason && <p className="text-destructive">{disabledReason}</p>}
      </div>
    </div>
  );
}
