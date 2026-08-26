"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

/**
 * The bar that appears once rows are selected (issue #210).
 *
 * Three lists each built their own. They agreed on the shape and disagreed on
 * everything else: whether the count was announced, whether a destructive
 * bulk action looked different from a benign one, and whether "clear" was a
 * button or an underlined span.
 *
 * Two things this fixes beyond consistency:
 *
 * **The count is announced.** Selecting rows with a keyboard changes a number
 * that a screen-reader user never hears, so they cannot tell how many rows
 * their next click will affect. `role="status"` reports it.
 *
 * **Destructive bulk actions read as destructive.** Not by painting the whole
 * bar red, #171 established that over-using the destructive colour drains
 * it of meaning, but by marking the specific action.
 */
export type BulkAction = {
  label: string;
  onClick: () => void;
  /** Marks an action that destroys or is hard to undo. Applied to that
   * action only, never the whole bar (see #171). */
  destructive?: boolean;
  disabled?: boolean;
};

export function BulkActionBar({
  count,
  itemNoun = "item",
  actions,
  onClear,
  children,
  className,
}: {
  count: number;
  /** Singular; pluralised automatically. "3 findings selected" reads better
   * than "3 finding(s) selected". */
  itemNoun?: string;
  actions?: BulkAction[];
  onClear: () => void;
  /** Extra controls, e.g. a shared reason input applied to the whole batch. */
  children?: React.ReactNode;
  className?: string;
}) {
  if (count === 0) return null;

  const label = `${count} ${itemNoun}${count === 1 ? "" : "s"} selected`;

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/50 p-3",
        className,
      )}
    >
      {/* role="status" rather than a bare span: the count changes as rows are
          ticked, and that change is the thing a non-visual user needs. */}
      <span role="status" className="text-xs font-medium text-foreground">
        {label}
      </span>

      {children}

      {actions?.map((action) => (
        <Button
          key={action.label}
          size="sm"
          variant={action.destructive ? "destructive" : "outline"}
          disabled={action.disabled}
          onClick={action.onClick}
          className="h-7 text-xs"
        >
          {action.label}
        </Button>
      ))}

      <button
        type="button"
        onClick={onClear}
        className="text-xs text-muted-foreground underline hover:text-foreground"
      >
        Clear selection
      </button>
    </div>
  );
}
