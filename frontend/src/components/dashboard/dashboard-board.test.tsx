import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { DashboardBoard } from "./dashboard-board";
import type { LayoutWidget, WidgetCatalogEntry, WidgetDataResponse } from "@/lib/api";

const saveDashboardLayout = vi.fn();
const dashboardWidgetData = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      saveDashboardLayout: (...args: unknown[]) => saveDashboardLayout(...args),
      dashboardWidgetData: (...args: unknown[]) => dashboardWidgetData(...args),
    },
  };
});

const CATALOG: WidgetCatalogEntry[] = [
  { widget_id: "kpi_cards", name: "Security Posture", description: "KPIs" },
  { widget_id: "top_risky_repos", name: "Top Risky Repos", description: "Riskiest repos" },
];

function kpiWidget(id = "w1"): LayoutWidget {
  return { id, widget_id: "kpi_cards", config: {} };
}

beforeEach(() => {
  saveDashboardLayout.mockReset();
  dashboardWidgetData.mockReset();
});

describe("DashboardBoard - layout read failure (data-loss guard)", () => {
  it("blocks editing entirely and never renders a Save control on top of an unread layout", () => {
    // The dangerous case: page.tsx's settledOr fallback for a failed layout
    // read is `{widgets: []}`, identical to a real empty dashboard. If this
    // component treated the two the same, "Edit Dashboard" -> "Save
    // Dashboard" would PUT that placeholder back as the user's new layout,
    // overwriting whatever they actually had saved with no undo.
    render(
      <DashboardBoard
        initialWidgets={[]}
        catalog={CATALOG}
        initialData={{ widgets: {} }}
        layoutFailed
        catalogFailed={false}
        dataFailed={false}
      />,
    );

    expect(screen.getByText(/Couldn't load your dashboard layout/)).not.toBeNull();
    // Neither the "Edit Dashboard" nor the empty-state's own edit CTA exists
    // in this render at all -- there is no path to Save.
    expect(screen.queryByRole("button", { name: /Edit Dashboard/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Save Dashboard/ })).toBeNull();
    expect(screen.queryByText(/Your dashboard is empty/)).toBeNull();
  });

  it("does not require a successful layout load to show a real, non-empty dashboard as failed", () => {
    // Even if the caller (a bug elsewhere) passed real widgets alongside
    // layoutFailed, the gate must still win -- the flag, not the widget
    // count, is what decides whether editing is safe.
    render(
      <DashboardBoard
        initialWidgets={[kpiWidget()]}
        catalog={CATALOG}
        initialData={{ widgets: {} }}
        layoutFailed
        catalogFailed={false}
        dataFailed={false}
      />,
    );
    expect(screen.getByText(/Couldn't load your dashboard layout/)).not.toBeNull();
    expect(screen.queryByText("Security Posture")).toBeNull();
  });
});

describe("DashboardBoard - widget data failure (no infinite Loading)", () => {
  it("renders a failed widget as failed, not stuck on Loading forever", () => {
    // page.tsx's fallback for a failed widget-data batch is `{widgets: {}}`,
    // so every widget's lookup is `undefined` -- indistinguishable from
    // "still in flight" unless dataFailed says otherwise.
    render(
      <DashboardBoard
        initialWidgets={[kpiWidget()]}
        catalog={CATALOG}
        initialData={{ widgets: {} }}
        layoutFailed={false}
        catalogFailed={false}
        dataFailed
      />,
    );
    expect(screen.queryByText("Loading...")).toBeNull();
    expect(screen.getByText(/Couldn't load widget/)).not.toBeNull();
  });

  it("still shows Loading for a widget added in edit mode, not yet saved, even if a stale batch failed", () => {
    // A widget added client-side has no entry in `data.widgets` regardless of
    // whether the last fetch succeeded -- that's a legitimately different
    // reason for "no entry" than a failed batch, and must not be repainted
    // as an error.
    render(
      <DashboardBoard
        initialWidgets={[kpiWidget("w1")]}
        catalog={CATALOG}
        initialData={{ widgets: { w1: { widget_id: "kpi_cards", data: { open: 1, critical: 0, targets: 1, mitigated: 0 } } } }}
        layoutFailed={false}
        catalogFailed={false}
        dataFailed
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Edit Dashboard/ }));
    fireEvent.click(screen.getByRole("button", { name: /Add Widget/ }));
    fireEvent.click(screen.getByText("Top Risky Repos"));

    // w1 (in the initial load) still has real data and renders it; the
    // freshly-added widget has no saved data yet and correctly still reads
    // "Loading...", not an error.
    expect(screen.getByText("Loading...")).not.toBeNull();
  });

  it("renders normally with no banner and no error cards when nothing failed", () => {
    render(
      <DashboardBoard
        initialWidgets={[kpiWidget("w1")]}
        catalog={CATALOG}
        initialData={{ widgets: { w1: { widget_id: "kpi_cards", data: { open: 3, critical: 1, targets: 2, mitigated: 0 } } } }}
        layoutFailed={false}
        catalogFailed={false}
        dataFailed={false}
      />,
    );
    expect(screen.queryByText(/Couldn't load widget/)).toBeNull();
    expect(screen.queryByText(/data source.*loaded/)).toBeNull();
    expect(screen.getByText("Open Findings")).not.toBeNull();
  });
});

describe("DashboardBoard - widget catalog failure", () => {
  it("surfaces the failed source in the shared partial-failure banner", () => {
    render(
      <DashboardBoard
        initialWidgets={[kpiWidget()]}
        catalog={[]}
        initialData={{ widgets: {} }}
        layoutFailed={false}
        catalogFailed
        dataFailed={false}
      />,
    );
    expect(screen.getByText("Widget catalog")).not.toBeNull();
    expect(screen.getByText(/can't be added right now/)).not.toBeNull();
  });
});
