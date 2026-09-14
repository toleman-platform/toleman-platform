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
 * Reusable progress indicator and metric meter.
 * 
 * Automatically applies semantic coloring based on standard health thresholds:
 * - >= 80%: Positive (Green / chart-5)
 * - >= 50%: Attention (Amber / chart-3)
 * - < 50%: Critical (Red / destructive)
 * 
 * Supports explicit tone overrides and tabular numeric readouts.
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
    <div className={cn("flex items-center gap-2.5", className)} {...props}>
      <div className={cn("relative w-full overflow-hidden rounded-full bg-secondary", sizeClass)}>
        <div
          className={cn("h-full rounded-full transition-all duration-500", toneClass)}
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
