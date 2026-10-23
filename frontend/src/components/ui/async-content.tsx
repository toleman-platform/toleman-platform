"use client";

import * as React from "react";
import { Inbox, SearchX } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { SkeletonList } from "@/components/ui/skeleton";
import type { UseAsyncDataResult } from "@/hooks/use-async-data";

/**
 * Shared async-request rendering with polite live status, aria-busy during background
 * refresh, and distinct filtered-empty versus no-data states. Keep previous rows during
 * refresh; offer clear-filters or initial-action guidance appropriate to the empty
 * state.
 */
export type AsyncContentProps<T> = {
  /** The result of `useAsyncData`. Passed whole rather than as loose props so
   * a caller cannot accidentally wire `isRefreshing` to the skeleton. */
  state: Pick<UseAsyncDataResult<T>, "status" | "data" | "error" | "isRefreshing" | "isInitialLoading" | "refetch">;
  children: (data: T) => React.ReactNode;

  /** Treat successful data as empty. Defaults to "array with no items". */
  isEmpty?: (data: T) => boolean;

  /** True when filters are active, which changes the empty copy and CTA.
   * Deliberately explicit: the component cannot infer whether a filter is
   * applied, and guessing produces the wrong dead end. */
  isFiltered?: boolean;
  onClearFilters?: () => void;

  emptyTitle?: string;
  emptyDescription?: string;
  emptyIcon?: React.ComponentType<{ className?: string }>;
  emptyAction?: React.ReactNode;

  errorTitle?: string;
  /** Skeleton rows while first loading. Match the real row count you expect
   * so the layout does not jump when data lands. */
  skeletonCount?: number;
  /** Replace the default skeleton entirely, for non-list shapes. */
  loadingFallback?: React.ReactNode;

  /** Describes the collection for screen-reader announcements: "Loaded 25
   * findings". Falls back to "items". */
  itemNoun?: string;
  className?: string;
};

function defaultIsEmpty(data: unknown): boolean {
  if (Array.isArray(data)) return data.length === 0;
  return false;
}

function countOf(data: unknown): number | null {
  return Array.isArray(data) ? data.length : null;
}

export function AsyncContent<T>({
  state,
  children,
  isEmpty = defaultIsEmpty,
  isFiltered = false,
  onClearFilters,
  emptyTitle,
  emptyDescription,
  emptyIcon,
  emptyAction,
  errorTitle,
  skeletonCount = 3,
  loadingFallback,
  itemNoun = "items",
  className,
}: AsyncContentProps<T>) {
  const { status, data, error, isRefreshing, isInitialLoading, refetch } = state;

  // The announcement is derived rather than fired from an effect: React
  // updates the live region's text content, and the assistive technology
  // announces the change. Doing it in an effect risks announcing twice under
  // StrictMode's double-invoke.
  const announcement = React.useMemo(() => {
    if (isInitialLoading) return `Loading ${itemNoun}`;
    if (status === "error") return `Failed to load ${itemNoun}`;
    if (status === "success") {
      const count = countOf(data);
      if (data !== null && isEmpty(data)) return `No ${itemNoun} found`;
      return count === null ? `${itemNoun} loaded` : `Loaded ${count} ${itemNoun}`;
    }
    return "";
    // isEmpty is a caller-provided predicate; including it would re-announce
    // on every render for inline arrows.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, data, isInitialLoading, itemNoun]);

  const body = (() => {
    if (isInitialLoading) return loadingFallback ?? <SkeletonList count={skeletonCount} />;

    // Error with no data at all: the error *is* the content.
    if (status === "error" && data === null) {
      return (
        <ErrorState
          title={errorTitle}
          description={error?.message}
          action={
            <Button size="sm" variant="outline" onClick={refetch}>
              Try again
            </Button>
          }
        />
      );
    }

    if (data === null) return null;

    if (isEmpty(data)) {
      // Filtered-empty and never-had-data are different problems with
      // different exits. See the component docblock.
      if (isFiltered) {
        return (
          <EmptyState
            icon={emptyIcon ?? SearchX}
            title={emptyTitle ?? `No ${itemNoun} match these filters`}
            description={emptyDescription ?? "Try widening or clearing your filters."}
            action={
              onClearFilters ? (
                <Button size="sm" variant="outline" onClick={onClearFilters}>
                  Clear filters
                </Button>
              ) : (
                emptyAction
              )
            }
          />
        );
      }
      return (
        <EmptyState
          icon={emptyIcon ?? Inbox}
          title={emptyTitle ?? `No ${itemNoun} yet`}
          description={emptyDescription}
          action={emptyAction}
        />
      );
    }

    return (
      <>
        {/* A refetch that failed keeps the stale rows; but says so, rather
            than presenting them as current. */}
        {status === "error" && (
          <div
            role="alert"
            className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
          >
            <span>Showing the last results, refresh failed: {error?.message}</span>
            <Button size="sm" variant="outline" className="h-6 text-xs" onClick={refetch}>
              Retry
            </Button>
          </div>
        )}
        {children(data)}
      </>
    );
  })();

  return (
    <div className={cn("relative", className)} aria-busy={isRefreshing || isInitialLoading}>
      {/* Visually hidden, always mounted. A live region added to the DOM at
          the same moment its text appears is frequently missed; keeping it
          mounted and mutating its text is the reliable pattern. */}
      <span aria-live="polite" aria-atomic="true" className="sr-only">
        {announcement}
      </span>
      {body}
    </div>
  );
}
