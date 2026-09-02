import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Icon as IconWrapper } from "@/components/ui/icon";
import Link from "next/link";

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
  value: React.ReactNode | null;
  /** Secondary line: units, provenance, or why the value is what it is. */
  hint?: string;
  icon?: React.ComponentType<{ className?: string }>;
  iconClass?: string;
  href?: string;
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

/**
 * Headline KPI metric card with label, optional icon, trend/context hint,
 * and first-class support for the unmeasured/unknown state (issue #210).
 */
export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  iconClass,
  href,
  unknown = false,
  unknownHint,
  tone = "default",
  className,
}: StatCardProps) {
  const content = (
    <CardContent className="flex items-center gap-3.5 px-4 py-3.5">
      {Icon && (
        <div
          aria-hidden="true"
          className={cn(
            "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-secondary text-muted-foreground transition-transform group-hover:scale-105",
            iconClass,
          )}
        >
          <IconWrapper icon={Icon} size="lg" />
        </div>
      )}
      <div className="min-w-0 flex-1">
        <div
          className={cn(
            "truncate font-mono text-2xl font-bold tabular-nums tracking-tight",
            unknown ? "text-muted-foreground/60" : TONE_CLASS[tone],
          )}
        >
          {unknown ? "—" : value}
        </div>
        <div className="truncate text-xs font-medium text-muted-foreground">{label}</div>
        {(unknown ? unknownHint : hint) && (
          <div className="truncate text-meta text-muted-foreground">
            {unknown ? unknownHint : hint}
          </div>
        )}
      </div>
    </CardContent>
  );

  if (href) {
    return (
      <Link href={href} className="group block no-underline">
        <Card
          className={cn(
            "interactive-surface border-border bg-card py-0 hover:border-primary/40",
            className,
          )}
        >
          {content}
        </Card>
      </Link>
    );
  }

  return (
    <Card className={cn("border-border bg-card py-0", className)}>
      {content}
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
