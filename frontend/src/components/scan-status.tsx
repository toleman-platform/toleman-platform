"use client";

import { Loader2, CheckCircle2, XCircle, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/**
 * How a scan's state reads, in one place (issue #212).
 *
 * Before this, triggering a scan produced a button that said "Scanning..."
 * for a moment and then nothing. The scan itself was invisible: no status on
 * the target row, none on the target detail page, and nothing at all for
 * API/DAST runs, whose longer durations made the silence worse. Every
 * surface that can show a scan now shares this component, so "running" looks
 * and reads the same everywhere.
 *
 * The states are deliberately four, not three. `queued` is the window
 * between dispatching the Celery task and the worker picking it up, and
 * collapsing it into `running` would claim work had started that may not
 * have -- the same class of overclaim as showing an ungrounded ETA.
 */
export type ScanPhase = "queued" | "running" | "completed" | "failed";

/** Compact duration for a countdown or a stopwatch: "45s", "2m 10s", "1h 3m".
 * Seconds are dropped past an hour, where they are noise. */
export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const minutes = Math.floor(s / 60);
  if (minutes < 60) {
    const rem = s % 60;
    return rem === 0 ? `${minutes}m` : `${minutes}m ${rem}s`;
  }
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return remMinutes === 0 ? `${hours}h` : `${hours}h ${remMinutes}m`;
}

/**
 * The progress line under a running scan.
 *
 * With enough history behind it, this is a real countdown. Without, it is a
 * stopwatch -- "running for 45s" is always true and needs no model behind
 * it, where a made-up "about 30 seconds" that turns into four minutes
 * teaches the user to distrust everything else on the page.
 *
 * A run that overshoots its estimate stops predicting rather than counting
 * into the negative or freezing at zero: the estimate was evidently wrong,
 * and saying so is more honest than insisting on it.
 */
export function scanProgressLabel(elapsedSeconds: number, etaSeconds: number | null): string {
  if (etaSeconds === null) return `running for ${formatDuration(elapsedSeconds)}`;
  const remaining = etaSeconds - elapsedSeconds;
  if (remaining <= 0) {
    return `running for ${formatDuration(elapsedSeconds)} · longer than usual`;
  }
  return `about ${formatDuration(remaining)} left`;
}

const PHASE_STYLE: Record<ScanPhase, string> = {
  queued: "border-border text-muted-foreground",
  running: "border-primary/40 bg-primary/10 text-accent-strong",
  completed: "border-chart-5/30 bg-chart-5/10 text-chart-5",
  failed: "border-destructive/40 bg-destructive/10 text-destructive",
};

const PHASE_LABEL: Record<ScanPhase, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

export function ScanStatusBadge({
  phase,
  tool,
  className,
}: {
  phase: ScanPhase;
  /** Shown alongside the phase when several tools run against one target, so
   * "Running" is attributable rather than ambiguous. */
  tool?: string;
  className?: string;
}) {
  const Icon =
    phase === "running" ? Loader2 : phase === "completed" ? CheckCircle2 : phase === "failed" ? XCircle : Clock;

  return (
    <Badge
      variant="outline"
      className={cn("inline-flex items-center gap-1.5 font-medium", PHASE_STYLE[phase], className)}
    >
      <Icon
        className={cn("h-3 w-3 shrink-0", phase === "running" && "animate-spin motion-reduce:animate-none")}
        aria-hidden="true"
      />
      <span>
        {PHASE_LABEL[phase]}
        {tool ? ` · ${tool}` : ""}
      </span>
    </Badge>
  );
}

/**
 * A running scan with its progress line, announced to assistive tech.
 *
 * `aria-live="polite"` on a region that is always mounted, rather than one
 * that appears with the scan: a live region announced only from the moment
 * it is inserted can miss its own first update.
 */
export function ScanProgress({
  phase,
  tool,
  elapsedSeconds,
  etaSeconds,
  error,
  className,
}: {
  phase: ScanPhase;
  tool?: string;
  elapsedSeconds?: number;
  etaSeconds?: number | null;
  /** Surfaced verbatim on failure. A scan that failed because the clone
   * timed out and one that failed because the tool is missing need different
   * responses from the user, and "Failed" alone distinguishes neither. */
  error?: string | null;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2 text-xs", className)}>
      <ScanStatusBadge phase={phase} tool={tool} />
      <span role="status" aria-live="polite" className="text-muted-foreground">
        {phase === "running" && elapsedSeconds !== undefined
          ? scanProgressLabel(elapsedSeconds, etaSeconds ?? null)
          : phase === "failed" && error
            ? error
            : ""}
      </span>
    </div>
  );
}
