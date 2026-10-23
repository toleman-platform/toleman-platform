import * as React from "react";
import { cn } from "@/lib/utils";

export interface ProgressBarProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number;
  max?: number;
  size?: "sm" | "md" | "lg";
  tone?: "auto" | "default" | "positive" | "attention" | "critical";
  showValue?: boolean;
  valueSuffix?: string;
}

/**
 * Accessible progress/metric meter with shared value/max for visual width and ARIA.
 * Auto tones: positive at >=80%, attention at >=50%, critical below; explicit tone
 * overrides and tabular numeric readouts are supported.
 */
export function ProgressBar({
  value,
  max = 100,
  size = "md",
  tone = "auto",
  showValue = false,
  valueSuffix = "%",
  className,
  ...props
}: ProgressBarProps) {
  const percentage = Math.min(Math.max(Math.round((value / max) * 100), 0), 100);

  // Loud in development, silent in production -- the same tradeoff
  // ListRow's missing-`selectLabel` warning makes (list-row.tsx): a
  // progressbar with no accessible name announces as "N percent, progress
  // bar" with nothing said about *what* is N percent, but that is a
  // real-content problem for each call site to fix, not one worth breaking
  // a user's page over.
  if (
    process.env.NODE_ENV !== "production" &&
    !props["aria-label"] &&
    !props["aria-labelledby"]
  ) {
    console.warn(
      "ProgressBar: pass `aria-label` (or `aria-labelledby`) so the progress meter has an accessible name.",
    );
  }

  const toneClass =
    tone === "positive"
      ? "bg-chart-5"
      : tone === "attention"
      ? "bg-chart-3"
      : tone === "critical"
      ? "bg-destructive"
      : tone === "default"
      ? "bg-primary"
      : percentage >= 80
      ? "bg-chart-5"
      : percentage >= 50
      ? "bg-chart-3"
      : "bg-destructive";

  const sizeClass = size === "sm" ? "h-1.5" : size === "lg" ? "h-3" : "h-2";

  return (
    <div
      role="progressbar"
      aria-valuenow={percentage}
      aria-valuemin={0}
      aria-valuemax={100}
      className={cn("flex items-center gap-2.5", className)}
      {...props}
    >
      <div className={cn("relative w-full overflow-hidden rounded-full bg-secondary", sizeClass)}>
        <div
          // `transition-[width]`, not `transition-all`: the only thing this
          // inner bar ever animates is its own width, so naming it is what
          // keeps the transition's scope intentional (see button.tsx for the
          // same fix). `motion-reduce` disables the animation outright
          // rather than merely speeding it up, matching drawer.tsx.
          className={cn("h-full rounded-full transition-[width] duration-500 motion-reduce:transition-none", toneClass)}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showValue && (
        <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
          {percentage}
          {valueSuffix}
        </span>
      )}
    </div>
  );
}
