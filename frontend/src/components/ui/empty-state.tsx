import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Shared "nothing here yet" state (#77) — icon + title + description + an
 * optional primary/secondary CTA. Replaces the app-wide pattern of a bare
 * `<p className="text-sm text-muted-foreground">No X yet.</p>` with
 * something that actually tells the user what to do next.
 *
 * Deliberately takes a `lucide-react` icon component (not an SVG string)
 * so every empty state stays on the app's single icon set.
 */
function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  secondaryAction,
  /** Drop the dashed border/background/large padding for use inside a
   * container that already has its own border (e.g. an admin tab's list
   * card) — keeps the icon + copy + CTA pattern without double-boxing. */
  bare = false,
  className,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description?: string;
  action?: React.ReactNode;
  secondaryAction?: React.ReactNode;
  bare?: boolean;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 text-center",
        bare ? "px-4 py-8" : "rounded-lg border border-dashed border-border bg-card/40 px-6 py-12",
        className
      )}
    >
      <div className={cn("flex items-center justify-center rounded-full bg-primary/10 text-primary", bare ? "h-9 w-9" : "h-12 w-12")}>
        <Icon className={bare ? "h-4 w-4" : "h-6 w-6"} />
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-sm font-semibold text-foreground">{title}</p>
        {description && (
          <p className="max-w-sm text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {(action || secondaryAction) && (
        <div className="mt-1 flex items-center gap-2">
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}

export { EmptyState };
