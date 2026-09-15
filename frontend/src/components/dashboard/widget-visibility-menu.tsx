"use client";

import { SlidersHorizontal } from "lucide-react";
import type { WidgetId } from "@/lib/api";
import { Button } from "@/components/ui/button";

export type WidgetVisibilityEntry = {
  widgetId: WidgetId;
  label: string;
};

/**
 * The dashboard's show/hide control: one checkbox per widget in the user's
 * layout, plus a way back to the default set for their role.
 *
 * Open state is owned by the caller so the "everything is hidden" state on
 * the board can point straight at this menu instead of leaving the reader to
 * find it.
 */
export function WidgetVisibilityMenu({
  entries,
  hidden,
  open,
  onOpenChange,
  onToggle,
  onReset,
  canPersist,
  saveFailed,
}: {
  /** Every widget in the layout, in layout order, already de-duplicated. */
  entries: readonly WidgetVisibilityEntry[];
  hidden: ReadonlySet<WidgetId>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onToggle: (widgetId: WidgetId) => void;
  onReset: () => void;
  /** False when a change cannot be stored: no known user, or a browser that
   * refuses this site storage. The menu still works for the current visit. */
  canPersist: boolean;
  /** True when the most recent change could not be stored. */
  saveFailed: boolean;
}) {
  const shown = entries.filter((e) => !hidden.has(e.widgetId)).length;

  return (
    <div className="relative">
      <Button
        type="button"
        variant="outline"
        size="sm"
        aria-expanded={open}
        onClick={() => onOpenChange(!open)}
      >
        <SlidersHorizontal className="h-3.5 w-3.5" />
        Widgets
        {/* Stating the count in the control itself, rather than only inside
            it, keeps a trimmed-down dashboard from reading as the whole
            picture. */}
        <span className="text-xs font-normal text-muted-foreground">
          {shown} of {entries.length}
        </span>
      </Button>

      {open && (
        <div className="absolute right-0 z-10 mt-1 w-72 rounded-md border border-border bg-card p-1 shadow-lg">
          <p className="px-2 pb-1 pt-1.5 text-xs font-medium text-muted-foreground">Shown on your dashboard</p>

          {entries.length === 0 && (
            <p className="px-2 py-1.5 text-xs text-muted-foreground">No widgets in this dashboard yet.</p>
          )}

          {entries.map((entry) => (
            <label
              key={entry.widgetId}
              className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-foreground hover:bg-accent/60"
            >
              <input
                type="checkbox"
                className="h-4 w-4 accent-primary"
                checked={!hidden.has(entry.widgetId)}
                onChange={() => onToggle(entry.widgetId)}
              />
              {entry.label}
            </label>
          ))}

          <div className="mt-1 border-t border-border px-1 py-1">
            <Button type="button" variant="ghost" size="sm" onClick={onReset}>
              Reset to default
            </Button>
          </div>

          {!canPersist && (
            <p className="px-2 pb-1.5 text-xs text-muted-foreground">
              These choices apply to this visit only; this browser is not storing them.
            </p>
          )}
          {saveFailed && canPersist && (
            <p className="px-2 pb-1.5 text-xs text-destructive">Your last change could not be saved.</p>
          )}
        </div>
      )}
    </div>
  );
}
