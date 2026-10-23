import { cookies } from "next/headers";
import { api, type WidgetDataResponse } from "@/lib/api";
import { DashboardBoard } from "@/components/dashboard/dashboard-board";
import { settledOr, settleOrNull } from "@/std-lib";
import { WORKSPACE_COOKIE_KEY, parseWorkspaceCookie } from "@/lib/workspace-cookie";

// Fetch initial dashboard data here; DashboardBoard owns editing. Preserve independent
// failures: a failed layout must not become an editable empty layout, failed widget
// data must not become perpetual loading, and catalog failure is partial. settledOr
// retains collection failure flags. Fetch the user separately because layout data is
// unavailable here; settleOrNull preserves unknown roles as show-everything rather than
// inventing a persona.
export default async function PosturePage() {
  // (#506) The global workspace switcher's active workspace, read from the
  // cookie WorkspaceContext keeps in sync (see lib/workspace-cookie.ts for
  // why this page needs the cookie rather than the context itself: this is
  // a Server Component, with no access to the client-side localStorage the
  // context otherwise reads). `undefined` (no cookie yet, or a stale one)
  // falls back to this endpoint's existing unfiltered/accessible-scope
  // default; `null` ("All workspaces") behaves the same way server-side.
  const activeWorkspaceId = parseWorkspaceCookie((await cookies()).get(WORKSPACE_COOKIE_KEY)?.value);
  const workspaceId = activeWorkspaceId ?? undefined;

  const [[layout, layoutFailed], [catalog, catalogFailed], [initialData, dataFailed], user] = await Promise.all([
    settledOr(api.dashboardLayout(), { widgets: [] }),
    settledOr(api.dashboardWidgets(), []),
    settledOr<WidgetDataResponse>(api.dashboardWidgetData(workspaceId), { widgets: {} }),
    settleOrNull(api.me()),
  ]);

  return (
    <DashboardBoard
      initialWidgets={layout.widgets}
      catalog={catalog}
      initialData={initialData}
      layoutFailed={layoutFailed}
      catalogFailed={catalogFailed}
      dataFailed={dataFailed}
      userId={user?.id ?? null}
      role={user?.role ?? null}
      profileFailed={user === null}
    />
  );
}
