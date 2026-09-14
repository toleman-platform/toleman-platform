import * as React from "react";
import { AlertTriangle, AlertCircle, CheckCircle2, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import { Icon as IconWrapper } from "@/components/ui/icon";

export interface AlertBannerProps extends Omit<React.HTMLAttributes<HTMLDivElement>, "title"> {
  tone?: "info" | "warning" | "critical" | "positive";
  title?: React.ReactNode;
  children: React.ReactNode;
  action?: React.ReactNode;
}

const TONE_CONFIG = {
  info: {
    icon: Info,
    container: "border-primary/30 bg-primary/10 text-foreground",
    iconClass: "text-primary",
  },
  warning: {
    icon: AlertTriangle,
    container: "border-chart-3/30 bg-chart-3/15 text-foreground",
    iconClass: "text-chart-3",
  },
  critical: {
    icon: AlertCircle,
    container: "border-destructive/30 bg-destructive/15 text-foreground",
    iconClass: "text-destructive",
  },
  positive: {
    icon: CheckCircle2,
    container: "border-chart-5/30 bg-chart-5/15 text-foreground",
    iconClass: "text-chart-5",
  },
};

/**
 * Standardized Contextual Alert Banner.
 * Designed for high-contrast security warnings, SLA notices, and status updates.
 */
export function AlertBanner({
  tone = "info",
  title,
  children,
  action,
  className,
  ...props
}: AlertBannerProps) {
  const config = TONE_CONFIG[tone];

  return (
    <div
      role="alert"
      className={cn(
        "flex items-start justify-between gap-3 rounded-lg border p-3.5 text-xs transition-colors",
        config.container,
        className
      )}
      {...props}
    >
      <div className="flex items-start gap-2.5 min-w-0">
        <IconWrapper icon={config.icon} size="md" className={cn("mt-0.5", config.iconClass)} />
        <div className="min-w-0 flex-1 space-y-0.5">
          {title && <div className="font-semibold text-foreground">{title}</div>}
          <div className="text-muted-foreground">{children}</div>
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
