import { jsonFetch } from "./client";
import type {
  Summary,
  SecurityScore,
  WidgetCatalogEntry,
  DashboardLayoutOut,
  LayoutWidget,
  WidgetDataResponse,
  Target,
} from "@/types";

/**
 * High-level counts of total, open, and mitigated findings, optionally
 * narrowed to the global workspace switcher's active workspace.
 */
export function summary(workspaceId?: number | null): Promise<Summary> {
  const qs = workspaceId != null ? `?workspace_id=${workspaceId}` : "";
  return jsonFetch<Summary>(`/api/dashboard/summary${qs}`);
}

/**
 * Breakdown of open findings categorized by severity and scanner tool,
 * optionally narrowed to the global workspace switcher's active workspace.
 */
export function stats(workspaceId?: number | null): Promise<{
  open: number;
  by_severity: Record<string, number>;
  by_tool: Record<string, number>;
}> {
  const qs = workspaceId != null ? `?workspace_id=${workspaceId}` : "";
  return jsonFetch<{
    open: number;
    by_severity: Record<string, number>;
    by_tool: Record<string, number>;
  }>(`/api/dashboard/stats${qs}`);
}

/**
 * Retrieves the composite security score (org-wide, or scoped to a target,
 * group, or the workspace switcher's active workspace -- targetId/groupId
 * take precedence over workspaceId server-side when more than one is given).
 */
export function securityScore(
  scope: { targetId?: number; groupId?: number; workspaceId?: number | null } = {},
): Promise<SecurityScore> {
  const params = new URLSearchParams();
  if (scope.targetId) params.set("target_id", String(scope.targetId));
  if (scope.groupId) params.set("group_id", String(scope.groupId));
  if (scope.workspaceId != null) params.set("workspace_id", String(scope.workspaceId));
  const qs = params.toString();
  return jsonFetch<SecurityScore>(`/api/dashboard/security-score${qs ? `?${qs}` : ""}`);
}

/**
 * Lists the catalog of available widgets for the dashboard.
 */
export function dashboardWidgets(): Promise<WidgetCatalogEntry[]> {
  return jsonFetch<WidgetCatalogEntry[]>("/api/dashboard/widgets");
}

/**
 * Fetches the caller's saved dashboard layout configuration.
 */
export function dashboardLayout(): Promise<DashboardLayoutOut> {
  return jsonFetch<DashboardLayoutOut>("/api/dashboard/layout");
}

/**
 * Saves changes to the caller's dashboard layout (widget order and configuration).
 */
export function saveDashboardLayout(widgets: LayoutWidget[]): Promise<DashboardLayoutOut> {
  return jsonFetch<DashboardLayoutOut>("/api/dashboard/layout", {
    method: "PUT",
    body: JSON.stringify({ widgets }),
  });
}

/**
 * Batched data retrieval for all active widgets currently in the caller's
 * layout, optionally narrowed to the global workspace switcher's active
 * workspace.
 */
export function dashboardWidgetData(workspaceId?: number | null): Promise<WidgetDataResponse> {
  const qs = workspaceId != null ? `?workspace_id=${workspaceId}` : "";
  return jsonFetch<WidgetDataResponse>(`/api/dashboard/widget-data${qs}`);
}

/**
 * Retrieves security posture metrics and breakdowns for all monitored
 * targets, optionally narrowed to the global workspace switcher's active
 * workspace.
 */
export function posture(
  workspaceId?: number | null,
): Promise<{ target: Target; breakdown: Record<string, Record<string, number>> }[]> {
  const qs = workspaceId != null ? `?workspace_id=${workspaceId}` : "";
  return jsonFetch<{ target: Target; breakdown: Record<string, Record<string, number>> }[]>(
    `/api/dashboard/posture${qs}`,
  );
}
