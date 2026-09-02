import * as React from "react";
import { CheckCircle2, AlertOctagon, Clock, Loader2, Ban, HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";

export type StatusVariant =
  | "running"
  | "completed"
  | "passed"
  | "failed"
  | "blocked"
  | "queued"
  | "pending"
  | "unknown";

export interface StatusBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  status: StatusVariant | string;
  label?: string;
  size?: "sm" | "md";
}

const STATUS_MAP: Record<
  string,
  { icon: React.ElementType; color: string; label: string; animate?: boolean }
> = {
  running: { icon: Loader2, color: "border-primary/40 bg-primary/10 text-primary", label: "Running", animate: true },
  queued: { icon: Clock, color: "border-chart-3/40 bg-chart-3/10 text-chart-3", label: "Queued" },
  pending: { icon: Clock, color: "border-chart-3/40 bg-chart-3/10 text-chart-3", label: "Pending" },
  completed: { icon: CheckCircle2, color: "border-chart-5/40 bg-chart-5/10 text-chart-5", label: "Completed" },
  passed: { icon: CheckCircle2, color: "border-chart-5/40 bg-chart-5/10 text-chart-5", label: "Passed" },
  failed: { icon: AlertOctagon, color: "border-destructive/40 bg-destructive/10 text-destructive", label: "Failed" },
  blocked: { icon: Ban, color: "border-destructive/40 bg-destructive/10 text-destructive", label: "Blocked" },
  unknown: { icon: HelpCircle, color: "border-border bg-secondary text-muted-foreground", label: "Unknown" },
};

/**
 * Standardized Lifecycle & Scan State Indicator badge.
 * Provides consistent color coding, icons, and animations across async tasks.
 */
export function StatusBadge({
  status,
  label,
  size = "md",
  className,
  ...props
}: StatusBadgeProps) {
  const norm = status.toLowerCase();
  const config = STATUS_MAP[norm] ?? STATUS_MAP.unknown;
  const Icon = config.icon;
  const displayLabel = label ?? config.label;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border font-medium transition-colors",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-0.5 text-xs",
        config.color,
        className
      )}
      {...props}
    >
      <Icon className={cn("h-3 w-3 shrink-0", config.animate && "animate-spin")} />
      <span>{displayLabel}</span>
    </span>
  );
}
