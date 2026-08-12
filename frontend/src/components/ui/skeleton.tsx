import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("animate-pulse rounded-md bg-secondary", className)}
      {...props}
    />
  );
}

/** A skeleton shaped like the `Card`/`CardContent` rows used throughout the
 * dashboard (e.g. finding/PR/audit-event list rows): an icon-ish block, two
 * stacked text lines, and a trailing badge-shaped block. */
function SkeletonCard({ className }: { className?: string }) {
  return (
    <Card className={cn("border-border bg-card", className)}>
      <CardContent className="flex items-center justify-between px-4 py-3">
        <div className="flex flex-1 flex-col gap-2">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-3 w-1/5" />
        </div>
        <Skeleton className="h-5 w-16 shrink-0" />
      </CardContent>
    </Card>
  );
}

/** A run of `SkeletonCard`s for list pages (audit log, PR history, etc). */
function SkeletonList({ count = 4, className }: { count?: number; className?: string }) {
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  );
}

export { Skeleton, SkeletonCard, SkeletonList };
