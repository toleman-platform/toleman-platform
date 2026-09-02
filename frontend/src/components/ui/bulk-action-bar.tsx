"use client";

import * as React from "react";
import { useEffect } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { X } from "lucide-react";
import { isNonEmptyArray } from "@/std-lib";

/**
 * High-visibility floating bottom action bar that anchors once items are selected.
 *
 * Enterprise triage ergonomics:
 * - Floating fixed position at viewport bottom, maintaining context during long scroll sessions.
 * - Screen-reader announcements via `role="status"` and `aria-live="polite"`.
 * - Keyboard `Esc` shortcut listener to quickly dismiss batch selection.
 * - Glassmorphism surface styling adhering to design system neutral surface tokens.
 */
export type BulkAction = {
  label: string;
  onClick: () => void;
  /** Marks an action that destroys or is hard to undo. */
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
  itemNoun?: string;
  actions?: BulkAction[];
  onClear: () => void;
  /** Extra controls, e.g. a shared reason input applied to the whole batch. */
  children?: React.ReactNode;
  className?: string;
}) {
  // Listen for Escape key to clear batch selection
  useEffect(() => {
    if (count === 0) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onClear();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [count, onClear]);

  if (count === 0) return null;

  const label = `${count} ${itemNoun}${count === 1 ? "" : "s"} selected`;

  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "fixed bottom-6 left-1/2 -translate-x-1/2 z-40 w-[94vw] max-w-4xl",
        "flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/80 bg-card/95 p-3.5 shadow-2xl backdrop-blur-md",
        "animate-in fade-in slide-in-from-bottom-3 duration-200",
        className,
      )}
    >
      {/* Selection count & blast radius indicator */}
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center gap-1 rounded-md bg-primary/15 px-2.5 py-1 font-mono text-xs font-bold text-accent-strong">
          {label}
        </span>
        <button
          type="button"
          onClick={onClear}
          title="Clear selection (Esc)"
          aria-label="Clear selection"
          className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
        >
          <X className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Clear</span>
          <kbd className="hidden sm:inline rounded border border-border bg-secondary px-1 text-[10px] font-mono text-muted-foreground">
            Esc
          </kbd>
        </button>
      </div>

      {/* Middle payload (e.g. Reason input) */}
      {children && <div className="flex flex-1 min-w-[200px] items-center gap-2">{children}</div>}

      {/* Batch Action Buttons */}
      {isNonEmptyArray(actions) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {actions.map((action) => (
            <Button
              key={action.label}
              size="sm"
              variant={action.destructive ? "destructive" : "outline"}
              disabled={action.disabled}
              onClick={action.onClick}
              className="h-7 text-xs font-medium"
            >
              {action.label}
            </Button>
          ))}
        </div>
      )}
    </div>
  );
}
