import { api, type WidgetDataResponse } from "@/lib/api";
import { DashboardBoard } from "@/components/dashboard/dashboard-board";

// Issue #69: dashboard composition is now per-user and configurable
// (widget catalog + saved layout), replacing the previous hardcoded card
// arrangement. This server component just does the initial fetch; all
// edit/add/remove/reorder/save interaction lives in <DashboardBoard>.
export default async function PosturePage() {
  const [layout, catalog] = await Promise.all([
    api.dashboardLayout().catch(() => ({ widgets: [] })),
    api.dashboardWidgets().catch(() => []),
  ]);
  const initialData: WidgetDataResponse = await api.dashboardWidgetData().catch(() => ({ widgets: {} }));

  return <DashboardBoard initialWidgets={layout.widgets} catalog={catalog} initialData={initialData} />;
}
