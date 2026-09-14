import { jsonFetch, apiBaseUrl, appendMulti, filenameFromContentDisposition } from "./client";
import type {
  AiBomView,
  Endpoint,
  DiscoveryRunResult,
  ScanRun,
  RunStatus,
  SbomComponent,
  SbomRunResult,
  MalwareCheckResult,
  SbomImportResult,
  SbomExportFormat,
  OrgSbomResult,
  AiStatus,
  AiRecentAnalysis,
  PolicyRule,
  PolicyRuleType,
  FalsePositiveRule,
  FpRuleStats,
  ReportSection,
  PostureReportOptions,
  PostureReportDownload,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Retrieves the AI Bill of Materials (AIBOM) for a target repository.
 */
export function aibom(targetId: number): Promise<AiBomView> {
  return jsonFetch<AiBomView>(`/api/sbom/${targetId}/aibom`);
}

/**
 * Retrieves AST-discovered API routes and endpoints for a target.
 */
export function getDiscoveredEndpoints(
  targetId: number,
): Promise<{ target_id: number; count: number; endpoints: Endpoint[] }> {
  return jsonFetch<{ target_id: number; count: number; endpoints: Endpoint[] }>(`/api/discovery/${targetId}`);
}

/**
 * Mark a discovered endpoint in or out of scope for active scanning (#469).
 * An excluded endpoint is never probed, including when it is part of an
 * explicit selection.
 */
/** Whether an active-scan credential is configured, and under which header
 * name. The stored value is never returned by the API (#470). */
export function getApiScanCredential(
  targetId: number,
): Promise<{ target_id: number; configured: boolean; header_name: string | null }> {
  return jsonFetch(`/api/api-scan/${targetId}/credential`);
}

/** Store (or replace) the credential the active scanner presents. */
export function setApiScanCredential(
  targetId: number,
  headerName: string,
  headerValue: string,
): Promise<{ target_id: number; configured: boolean; header_name: string | null }> {
  return jsonFetch(`/api/api-scan/${targetId}/credential`, {
    method: "PUT",
    body: JSON.stringify({ header_name: headerName, header_value: headerValue }),
  });
}

export function clearApiScanCredential(
  targetId: number,
): Promise<{ target_id: number; configured: boolean; header_name: string | null }> {
  return jsonFetch(`/api/api-scan/${targetId}/credential`, { method: "DELETE" });
}

/** One request with the stored credential, reporting whether it was
 * accepted. Catches the silent failure: a wrong token 401s every route and
 * the scan still reports zero findings. */
export function testApiScanCredential(
  targetId: number,
): Promise<{ target_id: number; status_code: number; accepted: boolean; detail: string }> {
  return jsonFetch(`/api/api-scan/${targetId}/credential/test`, { method: "POST" });
}

export function setEndpointScope(
  targetId: number,
  endpointId: number,
  excluded: boolean,
  reason?: string,
): Promise<{ id: number; method: string; route: string; excluded: boolean; exclusion_reason: string | null }> {
  return jsonFetch(`/api/discovery/${targetId}/endpoints/${endpointId}`, {
    method: "PATCH",
    body: JSON.stringify({ excluded, reason: reason ?? null }),
  });
}

/**
 * Dispatches an asynchronous endpoint discovery task.
 */
export function runDiscovery(
  targetId: number,
): Promise<{ run_id: number; target_id: number; status: RunStatus }> {
  return jsonFetch<{ run_id: number; target_id: number; status: RunStatus }>(`/api/discovery/${targetId}`, {
    method: "POST",
  });
}

/**
 * Polls the status and outcome of an endpoint discovery task.
 */
export function getDiscoveryRun(targetId: number, runId: number): Promise<DiscoveryRunResult> {
  return jsonFetch<DiscoveryRunResult>(`/api/discovery/${targetId}/runs/${runId}`);
}

/**
 * Triggers an active Nuclei vulnerability scan against discovered API endpoints.
 */
export function runApiScan(
  targetId: number,
  endpointIds?: number[],
): Promise<{ scan_id: number; target_id: number; status: RunStatus; endpoint_count: number }> {
  return jsonFetch<{ scan_id: number; target_id: number; status: RunStatus; endpoint_count: number }>(
    `/api/api-scan/${targetId}`,
    { method: "POST", body: JSON.stringify({ endpoint_ids: endpointIds ?? null }) },
  );
}

/**
 * Fetches the most recent API scan result for a target.
 */
export function getLatestApiScan(targetId: number): Promise<{ target_id: number; scan: Nullable<ScanRun> }> {
  return jsonFetch<{ target_id: number; scan: Nullable<ScanRun> }>(`/api/api-scan/${targetId}/latest`);
}

/**
 * Retrieves the Software Bill of Materials (SBOM) component list for a target.
 */
export function getSbom(targetId: number): Promise<{ target_id: number; count: number; components: SbomComponent[] }> {
  return jsonFetch<{ target_id: number; count: number; components: SbomComponent[] }>(`/api/sbom/${targetId}`);
}

/**
 * Dispatches an asynchronous SBOM generation job.
 */
export function generateSbom(targetId: number): Promise<{ run_id: number; target_id: number; status: RunStatus }> {
  return jsonFetch<{ run_id: number; target_id: number; status: RunStatus }>(`/api/sbom/${targetId}`, {
    method: "POST",
  });
}

/**
 * Polls an SBOM generation task until completion.
 */
export function getSbomRun(targetId: number, runId: number): Promise<SbomRunResult> {
  return jsonFetch<SbomRunResult>(`/api/sbom/${targetId}/runs/${runId}`);
}

/**
 * Re-checks an existing SBOM inventory against OSV.dev for newly reported malicious packages.
 */
export function malwareCheck(targetId: number): Promise<MalwareCheckResult> {
  return jsonFetch<MalwareCheckResult>(`/api/sbom/${targetId}/malware-check`, { method: "POST" });
}

/**
 * Imports dependencies from GitHub Dependency Graph into the target's SBOM inventory.
 */
export function importGithubSbom(targetId: number): Promise<SbomImportResult> {
  return jsonFetch<SbomImportResult>(`/api/sbom/${targetId}/github-sync`, { method: "POST" });
}

/**
 * Uploads an external CycloneDX or SPDX SBOM file (multipart form upload).
 */
export async function uploadSbom(targetId: number, file: File): Promise<SbomImportResult> {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${apiBaseUrl()}/api/sbom/${targetId}/upload`, {
    method: "POST",
    credentials: "include",
    body,
  });
  if (!res.ok) {
    let detail: string | undefined;
    try {
      const data = await res.json();
      if (data && typeof data.detail === "string") detail = data.detail;
    } catch {
      // Non-JSON response
    }
    throw new Error(detail || `SBOM upload failed: ${res.status}`);
  }
  return res.json();
}

/**
 * Exports a target's SBOM in CycloneDX, SPDX, CSV, or PDF format.
 */
export async function exportSbom(targetId: number, format: SbomExportFormat = "cyclonedx-json"): Promise<Blob> {
  const res = await fetch(`${apiBaseUrl()}/api/sbom/${targetId}/export?format=${format}`, { credentials: "include" });
  if (!res.ok) throw new Error(`export failed: ${res.status}`);
  return res.blob();
}

/**
 * Retrieves the organization-wide aggregated SBOM inventory.
 */
export function getOrgSbom(): Promise<OrgSbomResult> {
  return jsonFetch<OrgSbomResult>("/api/sbom/org");
}

/**
 * Exports the organization-wide SBOM catalog as a file blob.
 */
export async function exportOrgSbom(): Promise<Blob> {
  const res = await fetch(`${apiBaseUrl()}/api/sbom/org/export`, { credentials: "include" });
  if (!res.ok) throw new Error(`export failed: ${res.status}`);
  return res.blob();
}

/**
 * The selectable sections of the posture report (#302), served by the backend
 * rather than hardcoded here so the report builder can only ever offer
 * sections the renderers actually know how to produce.
 */
export function reportSections(): Promise<ReportSection[]> {
  return jsonFetch<ReportSection[]>("/api/reports/sections");
}

/**
 * Exports security posture report as CSV or PDF.
 *
 * `options` (#302) is everything beyond scope+format: the Findings-page
 * filters the report can be narrowed by, and which sections to include.
 * Omitted/empty means "no filter" and "every section", so the two-argument
 * call this had before #302 still produces the same full report.
 */
export async function exportPostureReport(
  targetId: Nullable<number>,
  format: "csv" | "pdf",
  options: PostureReportOptions = {},
): Promise<PostureReportDownload> {
  const params = new URLSearchParams({ format });
  if (targetId !== null && targetId !== 0) {
    params.set("target_id", String(targetId));
  }
  if (options.group_id) params.set("group_id", String(options.group_id));
  appendMulti(params, "severity", options.severity);
  appendMulti(params, "state", options.state);
  appendMulti(params, "tool", options.tool);
  if (options.category) params.set("category", options.category);
  if (options.environment) params.set("environment", options.environment);
  if (options.owner) params.set("owner", options.owner);
  if (options.date_from) params.set("date_from", options.date_from);
  if (options.date_to) params.set("date_to", options.date_to);
  appendMulti(params, "sections", options.sections);

  const res = await fetch(`${apiBaseUrl()}/api/reports/posture?${params.toString()}`, {
    credentials: "include",
  });
  if (!res.ok) throw new Error(`report export failed: ${res.status}`);
  return {
    blob: await res.blob(),
    // The server already names the file (scope, whether it was filtered, how
    // many sections it carries, date), so the filename is read back off the
    // response instead of rebuilt here. A client-side copy of that naming
    // rule would drift the moment either side changed, and a narrowed report
    // saved under a full report's name is the same honesty problem the
    // in-document filter header exists to prevent.
    filename: filenameFromContentDisposition(res.headers.get("Content-Disposition")),
  };
}

/**
 * Checks the status and configuration of the LLM/AI provider.
 */
export function aiStatus(): Promise<AiStatus> {
  return jsonFetch<AiStatus>("/api/ai/status");
}

/**
 * Requests an AI-assisted root cause and remediation analysis for a finding.
 */
export function analyzeFinding(findingId: number): Promise<{ finding_id: number; analysis: string }> {
  return jsonFetch<{ finding_id: number; analysis: string }>(`/api/ai/analyze/${findingId}`, { method: "POST" });
}

/**
 * Retrieves recent finding analyses performed by AI.
 */
export function aiRecentAnalyses(): Promise<AiRecentAnalysis[]> {
  return jsonFetch<AiRecentAnalysis[]>("/api/ai/recent");
}

/**
 * Lists all active policy rules for a workspace.
 */
export function listPolicies(workspaceId: number): Promise<PolicyRule[]> {
  return jsonFetch<PolicyRule[]>(`/api/policies?workspace_id=${workspaceId}`);
}

/**
 * Creates a new security policy rule in a workspace.
 */
export function createPolicy(p: {
  workspace_id: number;
  rule_type: PolicyRuleType;
  value: string;
  reason?: string;
}): Promise<PolicyRule> {
  return jsonFetch<PolicyRule>("/api/policies", { method: "POST", body: JSON.stringify(p) });
}

/**
 * Deletes a policy rule by ID.
 */
export function deletePolicy(id: number): Promise<PolicyRule> {
  return jsonFetch<PolicyRule>(`/api/policies/${id}`, { method: "DELETE" });
}

/**
 * Lists learned false-positive suppression rules in a workspace.
 */
export function fpRules(workspaceId?: number): Promise<FalsePositiveRule[]> {
  return jsonFetch<FalsePositiveRule[]>(`/api/fp-rules${workspaceId ? `?workspace_id=${workspaceId}` : ""}`);
}

/**
 * Retrieves aggregate false-positive auto-suppression statistics.
 */
export function fpRuleStats(workspaceId?: number): Promise<FpRuleStats> {
  return jsonFetch<FpRuleStats>(`/api/fp-rules/stats${workspaceId ? `?workspace_id=${workspaceId}` : ""}`);
}

/**
 * Activates or deactivates a learned false-positive rule.
 */
export function setFpRuleActive(id: number, active: boolean): Promise<FalsePositiveRule> {
  return jsonFetch<FalsePositiveRule>(`/api/fp-rules/${id}`, { method: "PATCH", body: JSON.stringify({ active }) });
}

/**
 * Widens a false-positive rule from file-specific to workspace-wide by clearing its file path pattern.
 */
export function widenFpRule(id: number): Promise<FalsePositiveRule> {
  return jsonFetch<FalsePositiveRule>(`/api/fp-rules/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ clear_file_path_pattern: true }),
  });
}

/**
 * Permanently deletes a false-positive suppression rule.
 */
export function deleteFpRule(id: number): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>(`/api/fp-rules/${id}`, { method: "DELETE" });
}
