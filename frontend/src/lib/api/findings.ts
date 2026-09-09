import { jsonFetch } from "./client";
import type {
  Finding,
  FindingListResult,
  FindingsQuery,
  FindingEnrichment,
  SlaRule,
  SlaComplianceData,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Retrieves a paginated and filtered list of findings.
 */
export function findings(query: FindingsQuery = {}): Promise<FindingListResult> {
  const params = new URLSearchParams();
  if (query.target_id) params.set("target_id", String(query.target_id));
  if (query.group_id) params.set("group_id", String(query.group_id));
  if (query.state) params.set("state", query.state);
  if (query.severity) params.set("severity", query.severity);
  if (query.tool) params.set("tool", query.tool);
  if (query.fixability) params.set("fixability", query.fixability);
  if (query.search) params.set("search", query.search);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  return jsonFetch<FindingListResult>(`/api/findings?${params.toString()}`);
}

/**
 * Triages a single finding to a new lifecycle state (e.g. "False Positive", "Mitigated", "Accepted Risk").
 */
export function triage(findingId: number, toState: string, reason: string): Promise<Finding> {
  return jsonFetch<Finding>(
    `/api/findings/${findingId}/triage?to_state=${encodeURIComponent(toState)}&reason=${encodeURIComponent(reason)}`,
    { method: "POST" },
  );
}

/**
 * Bulk triages multiple findings simultaneously.
 */
export function bulkTriage(
  findingIds: number[],
  toState: string,
  reason: string,
): Promise<{ updated: number; items: Finding[] }> {
  return jsonFetch<{ updated: number; items: Finding[] }>("/api/findings/bulk-triage", {
    method: "POST",
    body: JSON.stringify({ finding_ids: findingIds, to_state: toState, reason }),
  });
}

/**
 * Lists the distinct scanner tools currently represented in findings.
 */
export function findingTools(): Promise<string[]> {
  return jsonFetch<string[]>("/api/findings/facets/tools");
}

/**
 * Retrieves CVE, CWE, CVSS, and package fix-version enrichment data for a finding.
 */
export function findingEnrichment(findingId: number): Promise<FindingEnrichment> {
  return jsonFetch<FindingEnrichment>(`/api/findings/${findingId}/enrichment`);
}

/**
 * Lists all SLA rules defined for a workspace.
 */
export function slaRules(workspaceId?: number): Promise<SlaRule[]> {
  return jsonFetch<SlaRule[]>(`/api/sla-rules${workspaceId ? `?workspace_id=${workspaceId}` : ""}`);
}

/**
 * Creates a new SLA rule defining remediation timeframes by severity and optional group.
 */
export function createSlaRule(r: {
  workspace_id: number;
  group_id: Nullable<number>;
  severity: string;
  days_to_fix: number;
}): Promise<SlaRule> {
  return jsonFetch<SlaRule>("/api/sla-rules", {
    method: "POST",
    body: JSON.stringify(r),
  });
}

/**
 * Updates the days_to_fix threshold on an existing SLA rule.
 */
export function updateSlaRule(id: number, patch: { days_to_fix: number }): Promise<SlaRule> {
  return jsonFetch<SlaRule>(`/api/sla-rules/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Deletes an SLA rule.
 */
export function deleteSlaRule(id: number): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>(`/api/sla-rules/${id}`, { method: "DELETE" });
}

/**
 * Fetches aggregate organization-level SLA compliance metrics.
 */
export function slaCompliance(): Promise<SlaComplianceData> {
  return jsonFetch<SlaComplianceData>("/api/dashboard/sla-compliance");
}
