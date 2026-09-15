import { cookies } from "next/headers";
import { api, type WidgetDataResponse } from "@/lib/api";
import { DashboardBoard } from "@/components/dashboard/dashboard-board";
import { settledOr, settleOrNull } from "@/std-lib";
import { WORKSPACE_COOKIE_KEY, parseWorkspaceCookie } from "@/lib/workspace-cookie";

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
//
// The fourth fetch is the signed-in user, which drives which widgets a
// dashboard starts with: posture and trend for the people who report on
// them, the queue of outstanding work for the people who clear it. The
// surrounding (dashboard)/layout.tsx already reads /api/auth/me for the
// sidebar, but a Server Component cannot reach into its layout's data, so
// this asks again.
//
// `settleOrNull` rather than `settledOr` here, per that module's own rule:
// the fallback is a single object the page either has or does not have, not
// an empty collection, so `null` already carries the failure bit -- this
// endpoint cannot answer `null` successfully. A role we could not read is
// not a role, and must not be allowed to decay into a persona the user never
// picked, so `null` propagates as "show everything" rather than as a default
// persona.
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
