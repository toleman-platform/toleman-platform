"use client";

import * as React from "react";
import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

/**
 * Shared "failed to load" state (#77) — friendly message + a real retry
 * action, in place of the app-wide `.catch(() => [])` pattern that quietly
 * turned every fetch failure into an indistinguishable empty state. Callers
 * pass `onRetry` (typically a router.refresh() or a re-fetch of the same
 * request) rather than each page hand-rolling its own recovery UI.
 */
function ErrorState({
  title = "Couldn't load this data",
  description,
  onRetry,
  action,
  className,
}: {
  title?: string;
  description?: string;
  onRetry?: () => void;
  /** Custom recovery action, for callers (server components) that can't
   * pass an `onRetry` closure and instead render e.g. <ReloadButton />. */
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 px-6 py-10 text-center",
        className
      )}
    >
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10 text-destructive">
        <AlertTriangle className="h-6 w-6" />
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-sm font-semibold text-foreground">{title}</p>
        {description && (
          <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {(onRetry || action) && (
        <div className="mt-1">
          {onRetry ? (
            <Button size="sm" variant="outline" onClick={onRetry}>
              Try again
            </Button>
          ) : (
            action
          )}
        </div>
      )}
    </div>
  );
}

export { ErrorState };
