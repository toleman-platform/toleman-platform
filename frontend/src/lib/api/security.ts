import { jsonFetch, apiBaseUrl } from "./client";
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
 * Exports security posture report as CSV or PDF.
 */
export async function exportPostureReport(targetId: Nullable<number>, format: "csv" | "pdf"): Promise<Blob> {
  const params = new URLSearchParams({ format });
  if (targetId !== null && targetId !== 0) {
    params.set("target_id", String(targetId));
  }
  const res = await fetch(`${apiBaseUrl()}/api/reports/posture?${params.toString()}`, {
    credentials: "include",
  });
  if (!res.ok) throw new Error(`report export failed: ${res.status}`);
  return res.blob();
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
