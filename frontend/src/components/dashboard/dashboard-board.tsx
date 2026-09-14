"use client";

import { useState, useTransition } from "react";
import { Pencil, Save, Plus, X, LayoutGrid } from "lucide-react";
import {
  api,
  type LayoutWidget,
  type WidgetCatalogEntry,
  type WidgetDataEntry,
  type WidgetDataResponse,
  type WidgetId,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { PageHeader } from "@/components/ui/page-header";
import { PartialFailureBanner } from "@/components/ui/partial-failure-banner";
import { ReloadButton } from "@/components/reload-button";
import { WidgetShell } from "@/components/dashboard/widget-shell";
import { WidgetBody, WIDGET_META } from "@/components/dashboard/widgets";

function makeInstanceId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `w-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// Issue #69: the "Edit Dashboard" mode. Widget composition lives entirely
// client-side until Save; PUT /api/dashboard/layout persists the whole
// ordered list at once (add/remove/reorder all collapse to "save this
// list"), then a fresh GET /api/dashboard/widget-data pulls real data for
// whatever's now in the layout.
export function DashboardBoard({
  initialWidgets,
  catalog,
  initialData,
  layoutFailed,
  catalogFailed,
  dataFailed,
}: {
  initialWidgets: LayoutWidget[];
  catalog: WidgetCatalogEntry[];
  initialData: WidgetDataResponse;
  /** True when GET /api/dashboard/layout failed and `initialWidgets` is only
   * the `{widgets: []}` fallback, not a real answer. See the guard below --
   * this has to gate the whole edit/save path, not just the initial render. */
  layoutFailed: boolean;
  /** True when GET /api/dashboard/widgets failed and `catalog` is only `[]`.
   * Existing widgets are unaffected; only the "Add Widget" picker degrades. */
  catalogFailed: boolean;
  /** True when GET /api/dashboard/widget-data failed and `initialData` is
   * only `{widgets: {}}`. Surfaced per-widget below rather than here, since
   * WidgetBody already has a real "this widget failed" state. */
  dataFailed: boolean;
}) {
  const [widgets, setWidgets] = useState<LayoutWidget[]>(initialWidgets);
  const [data, setData] = useState<WidgetDataResponse>(initialData);
  const [editMode, setEditMode] = useState(false);
  const [showAddPicker, setShowAddPicker] = useState(false);
  const [saving, startSaving] = useTransition();
  const [error, setError] = useState<string | null>(null);

  // A layout read that failed must never be treated as "the user
  // saved zero widgets" -- `initialWidgets` here is just the fallback `[]`
  // from page.tsx's `settledOr`, not a real answer. If edit mode were allowed
  // to proceed on top of it, "Save Dashboard" would PUT that placeholder back
  // as the user's new layout, silently discarding whatever they actually had
  // saved, with no undo. So this has to be a hard stop before any of the
  // edit/add/remove/reorder/save state below is reachable at all -- not a
  // banner next to a still-functional Save button, an actual gate. The only
  // way back in is a real reload (there is no client-side re-fetch for a
  // server-fetched prop), same recovery `ReloadButton` gives every other
  // page whose primary server-side fetch failed.
  if (layoutFailed) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="Security Overview" description="Real-time security posture, default branches only" />
        <ErrorState
          title="Couldn't load your dashboard layout"
          description="Editing is turned off until this loads -- saving on top of an unread layout would overwrite what you actually have configured."
          action={<ReloadButton />}
        />
      </div>
    );
  }

  // A widget freshly added in edit mode (never saved, so never in any
  // widget-data response) legitimately has no data yet and must keep showing
  // "Loading..." -- that's still true and still resolves once Save
  // re-fetches. Only a widget that WAS part of the layout this page actually
  // loaded, and is still missing after a whole-batch failure, gets rewritten
  // as failed below; otherwise a legitimately in-flight widget would falsely
  // flip to an error card the moment `dataFailed` is true for an unrelated
  // reason.
  const initialWidgetIds = new Set(initialWidgets.map((w) => w.id));

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
      <PageHeader
        title="Security Overview"
        description="Real-time security posture, default branches only"
        actions={
          <>
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
          </>
        }
      />

      <PartialFailureBanner
        sources={[
          {
            label: "Widget catalog",
            failed: catalogFailed,
            consequence: "New widgets can't be added right now; the ones you already have are unaffected.",
          },
          {
            label: "Widget data",
            failed: dataFailed,
            consequence: 'Affected widgets below show their own "couldn\'t load" message instead of stale or blank data.',
          },
        ]}
        action={<ReloadButton />}
      />

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
          its un-shrunk max-content to that track-sizing pass, so one
          widget with a wide-but-shrinkable row (Security Score's gauge +
          score list) silently pushed the ENTIRE dashboard grid, and with it
          `<main>`, to ~1490px wide, horizontally overflowing every phone-
          width viewport, while every other widget rendered as if nothing
          were wrong. Tailwind's `grid-cols-1` compiles to
          `repeat(1, minmax(0, 1fr))`; the `minmax(0, ...)` is what forces
          the track to the container's real width and lets children shrink
          and wrap inside it normally, instead of `auto` sizing to content. */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {widgets.map((w, i) => {
          const meta = WIDGET_META[w.widget_id];
          if (!meta) return null;
          // `data.widgets[w.id]` is `undefined` both while a fresh
          // widget-data fetch is genuinely in flight and after one has failed
          // outright -- WidgetBody can't tell those apart on its own, and
          // defaults to "Loading...", which is correct for the first case and
          // permanent for the second. Rewrite only the second case: a widget
          // this page's initial load actually expected data for
          // (`initialWidgetIds`), still missing after the whole batch is
          // known (`dataFailed`) to have failed. A widget added in edit mode
          // just now is not in `initialWidgetIds` and correctly keeps
          // "Loading..." -- it has no saved data yet regardless of whether
          // the last fetch succeeded.
          const entry: WidgetDataEntry | undefined =
            data.widgets[w.id] ??
            (dataFailed && initialWidgetIds.has(w.id)
              ? { widget_id: w.widget_id, error: "dashboard data request failed" }
              : undefined);
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
              <WidgetBody entry={entry} />
            </WidgetShell>
          );
        })}
      </div>
    </div>
  );
}
