import { jsonFetch, appendMulti } from "./client";
import type {
  Finding,
  FindingListResult,
  FindingsQuery,
  FindingEnrichment,
  CategoryFacetsQuery,
  CategoryFacet,
  FindingFacets,
  FindingFacetsQuery,
  FindingGroupsQuery,
  FindingGroupListResult,
  FindingSuggestFix,
  RaiseFixPrResult,
  SlaRule,
  SlaComplianceData,
  ScoringWeights,
  FindingScoreBreakdown,
  RemediationPlanResponse,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Every filter GET /api/findings accepts, serialized in one place so the
 * list, the grouped list, the category tabs and the facet counts (#270) can
 * never drift on what a given filter means -- the backend shares one query
 * builder (app/api/findings.py::_filtered_findings_query) for exactly that
 * reason, and a count that disagrees with the list under it is worse than no
 * count. Paging and sorting are deliberately not here: only a list has pages
 * and an order.
 */
function findingFilterParams(query: FindingFacetsQuery): URLSearchParams {
  const params = new URLSearchParams();
  appendMulti(params, "target_id", query.target_id);
  if (query.group_id) params.set("group_id", String(query.group_id));
  if (query.workspace_id != null) params.set("workspace_id", String(query.workspace_id));
  appendMulti(params, "state", query.state);
  appendMulti(params, "severity", query.severity);
  appendMulti(params, "tool", query.tool);
  if (query.category) params.set("category", query.category);
  appendMulti(params, "exclude_category", query.exclude_category);
  appendMulti(params, "fixability", query.fixability);
  appendMulti(params, "environment", query.environment);
  appendMulti(params, "owner", query.owner);
  if (query.resolved !== undefined) params.set("resolved", String(query.resolved));
  if (query.search) params.set("search", query.search);
  if (query.new_since_days) params.set("new_since_days", String(query.new_since_days));
  return params;
}

/**
 * Retrieves a paginated and filtered list of findings.
 */
export function findings(query: FindingsQuery = {}): Promise<FindingListResult> {
  const params = findingFilterParams(query);
  appendMulti(params, "rule_id", query.rule_id);
  if (query.sort) params.set("sort", query.sort);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  return jsonFetch<FindingListResult>(`/api/findings?${params.toString()}`);
}

/**
 * Retrieves the findings list collapsed into one row per decision.
 *
 * Takes the same filters as `findings()` so switching between the flat and
 * grouped views changes how many rows the same findings are drawn as, never
 * which findings are in scope.
 */
export function findingGroups(query: FindingGroupsQuery = {}): Promise<FindingGroupListResult> {
  const params = findingFilterParams(query);
  if (query.sort) params.set("sort", query.sort);
  if (query.page) params.set("page", String(query.page));
  if (query.page_size) params.set("page_size", String(query.page_size));
  return jsonFetch<FindingGroupListResult>(`/api/findings/groups?${params.toString()}`);
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
 * (#270) Per-value counts for every filterable dimension in one call.
 *
 * One round-trip rather than seven: the filter bar needs all of them on
 * every page load, and seven separate calls is both slower and a way for
 * the numbers to disagree with each other mid-flight.
 */
export function findingFacets(query: FindingFacetsQuery = {}): Promise<FindingFacets> {
  return jsonFetch<FindingFacets>(`/api/findings/facets?${findingFilterParams(query).toString()}`);
}

/*
 * The plain option-list endpoints below are not what the Findings page reads
 * on a good day -- findingFacets() returns these option sets *with* their
 * counts in one call -- but they are what it degrades to when that call
 * fails: controls without numbers beat no controls at all, and an active
 * ?tool=semgrep you cannot see is an active filter you cannot clear.
 */

/**
 * Lists the distinct scanner tools currently represented in findings.
 */
export function findingTools(): Promise<string[]> {
  return jsonFetch<string[]>("/api/findings/facets/tools");
}

/**
 * Distinct environments among targets the caller can see (#251). A backend
 * facet that had no client until the report builder (#302) needed it; nulls
 * are already dropped server-side, so an org that has labelled nothing yet
 * gets [] and the filter is simply not offered.
 */
export function findingEnvironments(): Promise<string[]> {
  return jsonFetch<string[]>("/api/findings/facets/environments");
}

/**
 * Distinct owners among targets the caller can see (#251). Same contract as
 * findingEnvironments above.
 */
export function findingOwners(): Promise<string[]> {
  return jsonFetch<string[]>("/api/findings/facets/owners");
}

/**
 * Retrieves per-category finding counts for category tabs.
 */
export function findingCategories(query: CategoryFacetsQuery = {}): Promise<CategoryFacet[]> {
  return jsonFetch<CategoryFacet[]>(
    `/api/findings/facets/categories?${findingFilterParams(query).toString()}`,
  );
}

/**
 * Retrieves CVE, CWE, CVSS, and package fix-version enrichment data for a finding.
 */
export function findingEnrichment(findingId: number): Promise<FindingEnrichment> {
  return jsonFetch<FindingEnrichment>(`/api/findings/${findingId}/enrichment`);
}

/**
 * (#247) The smallest set of upgrades that would close the most open,
 * CVE-bearing findings on a target, most findings-closed first, plus the
 * enrichment coverage they were computed from -- see
 * backend/app/core/remediation.py::remediation_plan, PackageRemediation for
 * the two honesty properties every caller has to preserve, and
 * RemediationCoverage for why an empty `plans` cannot be read on its own.
 * Workspace-scoped like every other read here: a target_id outside the
 * caller's workspace 404s rather than returning another tenant's plan.
 */
export function findingRemediations(targetId: number): Promise<RemediationPlanResponse> {
  return jsonFetch<RemediationPlanResponse>(`/api/findings/remediations?target_id=${targetId}`);
}

/**
 * Generates an automated fix recommendation and patch preview for a finding.
 */
export function suggestFix(findingId: number): Promise<FindingSuggestFix> {
  return jsonFetch<FindingSuggestFix>(`/api/findings/${findingId}/suggest-fix`, { method: "POST" });
}

/**
 * Opens a pull request against GitHub with the suggested remediation patch.
 */
export function raiseFixPr(
  findingId: number,
  patch: {
    file_path: string;
    new_content: string;
    ref: string;
    strategy: "ai" | "deterministic_sca";
    explanation: string;
  },
): Promise<RaiseFixPrResult> {
  return jsonFetch<RaiseFixPrResult>(`/api/findings/${findingId}/raise-pr`, {
    method: "POST",
    body: JSON.stringify(patch),
  });
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
 * Fetches aggregate SLA compliance metrics, optionally narrowed to the
 * global workspace switcher's active workspace.
 */
export function slaCompliance(workspaceId?: number | null): Promise<SlaComplianceData> {
  const qs = workspaceId != null ? `?workspace_id=${workspaceId}` : "";
  return jsonFetch<SlaComplianceData>(`/api/dashboard/sla-compliance${qs}`);
}

// (#201) Workspace-scoped risk-scoring weights. All three return the full
// effective configuration, so the caller never has to merge a mutation's
// result back into a list it is holding.

/**
 * Retrieves a workspace's effective risk-scoring weights.
 */
export function scoringWeights(workspaceId: number): Promise<ScoringWeights> {
  return jsonFetch<ScoringWeights>(`/api/scoring-weights?workspace_id=${workspaceId}`);
}

/**
 * Sets one signal's weight for a workspace.
 */
export function setScoringWeight(w: {
  workspace_id: number;
  signal: string;
  weight: number;
}): Promise<ScoringWeights> {
  return jsonFetch<ScoringWeights>("/api/scoring-weights", { method: "PUT", body: JSON.stringify(w) });
}

/**
 * Reverts one signal to the shipped baseline by dropping the override row.
 */
export function resetScoringWeight(ruleId: number): Promise<ScoringWeights> {
  return jsonFetch<ScoringWeights>(`/api/scoring-weights/${ruleId}`, { method: "DELETE" });
}

/**
 * Why this finding's priority score is the number it is (#201). Computed
 * server-side from the workspace's weights and whatever enrichment is
 * cached; never fetches from NVD, so this cannot hang on an upstream.
 */
export function findingScoreBreakdown(findingId: number): Promise<FindingScoreBreakdown> {
  return jsonFetch<FindingScoreBreakdown>(`/api/findings/${findingId}/score-breakdown`);
}
