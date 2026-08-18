"use client";

import { useState, useTransition } from "react";
import { Pencil, Save, Plus, X, LayoutGrid } from "lucide-react";
import { api, type LayoutWidget, type WidgetCatalogEntry, type WidgetDataResponse, type WidgetId } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { WidgetShell } from "@/components/dashboard/widget-shell";
import { WidgetBody, WIDGET_META } from "@/components/dashboard/widgets";

function makeInstanceId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `w-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// Issue #69: the "Edit Dashboard" mode. Widget composition lives entirely
// client-side until Save -- PUT /api/dashboard/layout persists the whole
// ordered list at once (add/remove/reorder all collapse to "save this
// list"), then a fresh GET /api/dashboard/widget-data pulls real data for
// whatever's now in the layout.
export function DashboardBoard({
  initialWidgets,
  catalog,
  initialData,
}: {
  initialWidgets: LayoutWidget[];
  catalog: WidgetCatalogEntry[];
  initialData: WidgetDataResponse;
}) {
  const [widgets, setWidgets] = useState<LayoutWidget[]>(initialWidgets);
  const [data, setData] = useState<WidgetDataResponse>(initialData);
  const [editMode, setEditMode] = useState(false);
  const [showAddPicker, setShowAddPicker] = useState(false);
  const [saving, startSaving] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const move = (index: number, direction: -1 | 1) => {
    setWidgets((prev) => {
      const next = [...prev];
      const target = index + direction;
      if (target < 0 || target >= next.length) return prev;
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  };

  const remove = (id: string) => {
    setWidgets((prev) => prev.filter((w) => w.id !== id));
  };

  const addWidget = (widgetId: WidgetId) => {
    setWidgets((prev) => [...prev, { id: makeInstanceId(), widget_id: widgetId, config: {} }]);
    setShowAddPicker(false);
  };

  const save = () => {
    setError(null);
    startSaving(async () => {
      try {
        const saved = await api.saveDashboardLayout(widgets);
        setWidgets(saved.widgets);
        const fresh = await api.dashboardWidgetData();
        setData(fresh);
        setEditMode(false);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to save dashboard");
      }
    });
  };

  const widgetIdsInUse = new Set(widgets.map((w) => w.widget_id));
  const addable = catalog.filter((c) => !widgetIdsInUse.has(c.widget_id));

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Overview</h1>
          <p className="text-sm text-muted-foreground">Real-time security posture, default branches only</p>
        </div>
        <div className="flex items-center gap-2">
          {editMode && (
            <div className="relative">
              <Button type="button" variant="outline" size="sm" onClick={() => setShowAddPicker((s) => !s)} disabled={addable.length === 0}>
                <Plus className="h-3.5 w-3.5" />
                Add Widget
              </Button>
              {showAddPicker && (
                <div className="absolute right-0 z-10 mt-1 w-64 rounded-md border border-border bg-card p-1 shadow-lg">
                  {addable.length === 0 && <p className="px-2 py-1.5 text-xs text-muted-foreground">All widgets already added</p>}
                  {addable.map((c) => (
                    <button
                      key={c.widget_id}
                      type="button"
                      onClick={() => addWidget(c.widget_id)}
                      className="block w-full rounded-sm px-2 py-1.5 text-left text-sm text-foreground hover:bg-accent/60"
                    >
                      {c.name}
                      <span className="block text-xs text-muted-foreground">{c.description}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
          {editMode ? (
            <>
              <Button type="button" variant="ghost" size="sm" onClick={() => { setWidgets(initialWidgets); setEditMode(false); setError(null); }}>
                <X className="h-3.5 w-3.5" />
                Cancel
              </Button>
              <Button type="button" size="sm" onClick={save} disabled={saving || widgets.length === 0}>
                <Save className="h-3.5 w-3.5" />
                {saving ? "Saving..." : "Save Dashboard"}
              </Button>
            </>
          ) : (
            <Button type="button" variant="outline" size="sm" onClick={() => setEditMode(true)}>
              <Pencil className="h-3.5 w-3.5" />
              Edit Dashboard
            </Button>
          )}
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {widgets.length === 0 && (
        <EmptyState
          icon={LayoutGrid}
          title="Your dashboard is empty"
          description={editMode ? 'Use "Add Widget" above to add one.' : 'Click "Edit Dashboard" to add widgets.'}
          action={
            !editMode && (
              <Button type="button" size="sm" onClick={() => setEditMode(true)}>
                <Pencil className="h-3.5 w-3.5" />
                Edit Dashboard
              </Button>
            )
          }
        />
      )}

      {/* `grid-cols-1` below `lg:` is load-bearing, not decorative (#224): an
          implicit single-column grid (no `grid-template-columns` at all,
          which is what this was before `lg:` kicks in) sizes that column to
          the widest child's max-content instead of clamping it to the
          container's actual width. A grid item that can genuinely shrink at
          layout time (a flex row that would happily wrap) still contributes
          its un-shrunk max-content to that track-sizing pass -- so one
          widget with a wide-but-shrinkable row (Security Score's gauge +
          score list) silently pushed the ENTIRE dashboard grid, and with it
          `<main>`, to ~1490px wide, horizontally overflowing every phone-
          width viewport, while every other widget rendered as if nothing
          were wrong. Tailwind's `grid-cols-1` compiles to
          `repeat(1, minmax(0, 1fr))` -- the `minmax(0, ...)` is what forces
          the track to the container's real width and lets children shrink
          and wrap inside it normally, instead of `auto` sizing to content. */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {widgets.map((w, i) => {
          const meta = WIDGET_META[w.widget_id];
          if (!meta) return null;
          return (
            <WidgetShell
              key={w.id}
              icon={meta.icon}
              title={meta.label}
              editMode={editMode}
              isFirst={i === 0}
              isLast={i === widgets.length - 1}
              onMoveUp={() => move(i, -1)}
              onMoveDown={() => move(i, 1)}
              onRemove={() => remove(w.id)}
              colSpanClass={meta.colSpanClass}
            >
              <WidgetBody entry={data.widgets[w.id]} />
            </WidgetShell>
          );
        })}
      </div>
    </div>
  );
}
