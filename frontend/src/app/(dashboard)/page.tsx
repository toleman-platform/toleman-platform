import { api, type WidgetDataResponse } from "@/lib/api";
import { DashboardBoard } from "@/components/dashboard/dashboard-board";
import { settledOr } from "@/std-lib";

// Issue #69: dashboard composition is now per-user and configurable
// (widget catalog + saved layout), replacing the previous hardcoded card
// arrangement. This server component just does the initial fetch; all
// edit/add/remove/reorder/save interaction lives in <DashboardBoard>.
//
// These three fetches used to swallow a rejected promise into an empty
// result -- `.catch(() => ({widgets: []}))`, `.catch(() => [])`,
// `.catch(() => ({widgets: {}}))`. That throws away exactly the bit that
// separates "the API answered with nothing" from "the API did not answer",
// which is a real bug in two different ways:
//
//  - For the layout fetch, `{widgets: []}` is what a user who has never
//    configured a dashboard *also* looks like. DashboardBoard renders that
//    unconditionally as "Your dashboard is empty" and lets the user hit Save,
//    which PUTs the placeholder back as their new layout -- overwriting
//    whatever they actually had, with no undo. See `layoutFailed` below.
//  - For the widget-data fetch, every widget's data lookup
//    (`data.widgets[w.id]`) comes back `undefined` either way -- "still
//    loading" and "the batch request failed and nothing will ever arrive" are
//    indistinguishable, so a failure just froze every widget on "Loading..."
//    forever. (The catalog fetch degrades more mildly: it only feeds the
//    "Add Widget" picker, so a failure there is surfaced as a partial-failure
//    banner rather than gating anything.)
//
// `settledOr` (std-lib/async.ts) keeps the failure bit alive past this fetch
// so DashboardBoard can render each failure as what it is instead of a
// confident empty state.
export default async function PosturePage() {
  const [[layout, layoutFailed], [catalog, catalogFailed], [initialData, dataFailed]] = await Promise.all([
    settledOr(api.dashboardLayout(), { widgets: [] }),
    settledOr(api.dashboardWidgets(), []),
    settledOr<WidgetDataResponse>(api.dashboardWidgetData(), { widgets: {} }),
  ]);

  return (
    <DashboardBoard
      initialWidgets={layout.widgets}
      catalog={catalog}
      initialData={initialData}
      layoutFailed={layoutFailed}
      catalogFailed={catalogFailed}
      dataFailed={dataFailed}
    />
  );
}
