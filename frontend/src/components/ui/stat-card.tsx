import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";

/**
 * A single headline number with its label (issue #210).
 *
 * Promoted out of the target Overview, where the same shape already existed
 * in three places (dashboard KPI cards, SBOM counts, target posture) with
 * three different paddings and two different label sizes.
 *
 * The `value` is typed `React.ReactNode` rather than `string` on purpose: a
 * count with a severity breakdown beside it ("1137" + "3H") is a legitimate
 * value, and forcing callers to stringify it pushed them back to hand-rolling
 * the card.
 *
 * `unknown` is a first-class variant, not an afterthought. Across this
 * codebase the distinction between "we measured zero" and "we have not
 * measured" keeps mattering; an unscanned repository is not a clean one
 * (#174), an ungenerated AIBOM is not an absence of models (#190). A stat
 * card that renders a confident `0` for missing data actively misinforms, so
 * the unknown case is built in and styled differently.
 */
export type StatCardProps = {
  label: string;
  value: React.ReactNode;
  /** Secondary line: units, provenance, or why the value is what it is. */
  hint?: string;
  icon?: React.ComponentType<{ className?: string }>;
  /** Render as "not measured" rather than showing `value`. */
  unknown?: boolean;
  /** Copy for the unknown case. Say what is missing, not just "n/a". */
  unknownHint?: string;
  /** Emphasis for a value that needs attention. `attention` is amber (not an
   * error, but not fine); `critical` is the destructive token. */
  tone?: "default" | "attention" | "critical" | "positive";
  className?: string;
};

const TONE_CLASS: Record<NonNullable<StatCardProps["tone"]>, string> = {
  default: "text-foreground",
  attention: "text-chart-3",
  critical: "text-destructive",
  positive: "text-chart-5",
};

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  unknown = false,
  unknownHint,
  tone = "default",
  className,
}: StatCardProps) {
  return (
    <Card className={cn("border-border bg-card py-0", className)}>
      <CardContent className="flex items-center gap-3 px-4 py-4">
        {Icon && (
          <div
            aria-hidden="true"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground"
          >
            <Icon className="h-4 w-4" />
          </div>
        )}
        <div className="min-w-0">
          <div
            className={cn(
              "truncate text-lg font-semibold",
              unknown ? "text-muted-foreground/60" : TONE_CLASS[tone],
            )}
          >
            {/* An em dash, not "0". The difference between unmeasured and
                measured-zero is the whole point of this variant. */}
            {unknown ? "—" : value}
          </div>
          <div className="truncate text-xs text-muted-foreground">{label}</div>
          {(unknown ? unknownHint : hint) && (
            <div className="truncate text-[11px] text-muted-foreground/70">
              {unknown ? unknownHint : hint}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Responsive grid for a row of StatCards. Exists so every stat row breaks at
 * the same points instead of each caller inventing its own column counts --
 * the dashboard, the target Overview and the SBOM summary previously used
 * three different sets.
 */
export function StatGrid({
  children,
  columns = 4,
  className,
}: {
  children: React.ReactNode;
  /** Column count at the widest breakpoint. Narrower breakpoints step down
   * automatically; a fixed grid at 390px produces unreadable slivers. */
  columns?: 2 | 3 | 4;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "grid grid-cols-1 gap-3 sm:grid-cols-2",
        columns === 3 && "lg:grid-cols-3",
        columns === 4 && "lg:grid-cols-4",
        className,
      )}
    >
      {children}
    </div>
  );
}
