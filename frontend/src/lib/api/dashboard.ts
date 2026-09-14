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
 * High-level counts of total, open, and mitigated findings.
 */
export function summary(): Promise<Summary> {
  return jsonFetch<Summary>("/api/dashboard/summary");
}

/**
 * Breakdown of open findings categorized by severity and scanner tool.
 */
export function stats(): Promise<{
  open: number;
  by_severity: Record<string, number>;
  by_tool: Record<string, number>;
}> {
  return jsonFetch<{
    open: number;
    by_severity: Record<string, number>;
    by_tool: Record<string, number>;
  }>("/api/dashboard/stats");
}

/**
 * Retrieves the composite security score (org-wide, or scoped to a target or group).
 */
export function securityScore(scope: { targetId?: number; groupId?: number } = {}): Promise<SecurityScore> {
  const params = new URLSearchParams();
  if (scope.targetId) params.set("target_id", String(scope.targetId));
  if (scope.groupId) params.set("group_id", String(scope.groupId));
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
 * Batched data retrieval for all active widgets currently in the caller's layout.
 */
export function dashboardWidgetData(): Promise<WidgetDataResponse> {
  return jsonFetch<WidgetDataResponse>("/api/dashboard/widget-data");
}

/**
 * Retrieves security posture metrics and breakdowns for all monitored targets.
 */
export function posture(): Promise<{ target: Target; breakdown: Record<string, Record<string, number>> }[]> {
  return jsonFetch<{ target: Target; breakdown: Record<string, Record<string, number>> }[]>(
    "/api/dashboard/posture",
  );
}
