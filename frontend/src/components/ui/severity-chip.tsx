import * as React from "react";
import { cn } from "@/lib/utils";
import { SEVERITY_COLOR } from "@/lib/severity";

export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface SeverityChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  severity: SeverityLevel | string;
  variant?: "solid" | "outline" | "subtle" | "dot";
  size?: "sm" | "md" | "lg";
  count?: number;
}

const DOT_COLOR: Record<string, string> = {
  Critical: "bg-destructive",
  High: "bg-chart-3",
  Medium: "bg-chart-1",
  Low: "bg-chart-2",
  Info: "bg-chart-2",
};

/**
 * Standardized Severity & Risk Badge component.
 * 
 * Supports solid, outline, subtle tint, and dot indicator variants with
 * guaranteed WCAG AA contrast compliance across both Dark and Light themes.
 */
export function SeverityChip({
  severity,
  variant = "subtle",
  size = "md",
  count,
  className,
  ...props
}: SeverityChipProps) {
  const norm = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
  const colorClass = SEVERITY_COLOR[norm] ?? "border-border bg-secondary text-muted-foreground";
  const dotBg = DOT_COLOR[norm] ?? "bg-muted-foreground";

  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-[10px]",
    md: "px-2 py-0.5 text-xs",
    lg: "px-2.5 py-1 text-xs font-semibold",
  }[size];

  if (variant === "dot") {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 font-medium text-foreground",
          size === "sm" ? "text-xs" : "text-sm",
          className
        )}
        {...props}
      >
        <span className={cn("h-2 w-2 rounded-full", dotBg)} aria-hidden="true" />
        <span>{norm}</span>
        {count !== undefined && (
          <span className="font-mono text-xs tabular-nums text-muted-foreground">({count})</span>
        )}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border font-medium transition-colors",
        sizeClasses,
        colorClass,
        className
      )}
      {...props}
    >
      <span>{norm}</span>
      {count !== undefined && (
        <span className="font-mono font-bold tabular-nums">({count})</span>
      )}
    </span>
  );
}
