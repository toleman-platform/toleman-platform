import { jsonFetch } from "./client";
import { DEFAULT_PAGE_SIZE } from "@/lib/pagination";
import type {
  ScanRun,
  RunStatus,
  ScanSummary,
  ActiveScans,
  ActivePrScans,
  ScanHistoryEntry,
  ToolRegistryEntry,
  ToolInstallRun,
  ToolAssignment,
  PrGuardrailScanResult,
  PrGuardrailLogEntry,
  PrGuardrailOrgLog,
  PrGuardrailFinding,
  PrGuardrailFindingPage,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Dispatches an on-demand scan for a specific scanner tool against a target.
 * Returns immediately with status: "running"; consumers should poll getScan(scan_id).
 */
export function runScan(
  targetId: number,
  tool: string,
): Promise<{ scan_id: number; status: RunStatus } | { error: string }> {
  return jsonFetch<{ scan_id: number; status: RunStatus } | { error: string }>(
    `/api/scans/run?target_id=${targetId}&tool=${tool}`,
    { method: "POST" },
  );
}

/**
 * Retrieves the status and outcome of an individual scan execution.
 */
export function getScan(scanId: number): Promise<ScanRun | { error: string }> {
  return jsonFetch<ScanRun | { error: string }>(`/api/scans/${scanId}`);
}

/**
 * Retrieves summary metadata for the latest scans across all targets.
 */
export function scanSummary(): Promise<ScanSummary> {
  return jsonFetch<ScanSummary>("/api/scans/summary");
}

/**
 * Fetches all currently executing scans across all targets.
 */
export function activeScans(): Promise<ActiveScans> {
  return jsonFetch<ActiveScans>("/api/scans/active");
}

/**
 * Fetches all currently executing PR Guardrail scans.
 */
export function activePrScans(): Promise<ActivePrScans> {
  return jsonFetch<ActivePrScans>("/api/pr-guardrail/active");
}

/**
 * Fetches historical scan runs for a specific target repository.
 */
export function scanHistory(
  targetId: number,
  page = 1,
  pageSize = 25,
): Promise<{ total: number; items: ScanHistoryEntry[] }> {
  return jsonFetch<{ total: number; items: ScanHistoryEntry[] }>(
    `/api/scans/history?target_id=${targetId}&page=${page}&page_size=${pageSize}`,
  );
}

/**
 * Health check endpoint for core built-in scanner binaries.
 */
export function toolsHealth(): Promise<
  { tool: string; installed: boolean; version: Nullable<string>; response_ms: Nullable<number> }[]
> {
  return jsonFetch<{ tool: string; installed: boolean; version: Nullable<string>; response_ms: Nullable<number> }[]>(
    "/api/tools/health",
  );
}

/**
 * Full tool catalog from the OSS tool registry with installation status.
 */
export function toolsRegistry(): Promise<ToolRegistryEntry[]> {
  return jsonFetch<ToolRegistryEntry[]>("/api/tools/registry");
}

/**
 * Dispatches a background job to install a scanner tool onto the Celery worker.
 */
export function installTool(tool: string): Promise<ToolInstallRun> {
  return jsonFetch<ToolInstallRun>(`/api/tools/${encodeURIComponent(tool)}/install`, { method: "POST" });
}

/**
 * Polls the progress and output tail of a tool installation job.
 */
export function getToolInstall(runId: number): Promise<ToolInstallRun> {
  return jsonFetch<ToolInstallRun>(`/api/tools/installs/${runId}`);
}

/**
 * Active tool installs currently running on the worker.
 */
export function activeToolInstalls(): Promise<Record<string, ToolInstallRun>> {
  return jsonFetch<Record<string, ToolInstallRun>>("/api/tools/installs/active");
}

/**
 * Retrieves the tool assignment matrix for a workspace.
 */
export function toolAssignments(workspaceId: number): Promise<ToolAssignment[]> {
  return jsonFetch<ToolAssignment[]>(`/api/tools/assignments?workspace_id=${workspaceId}`);
}

/**
 * Saves a tool assignment configuring which workflows a scanner runs in.
 */
export function saveToolAssignment(a: {
  workspace_id: number;
  tool: string;
  on_demand_scan: boolean;
  ci_pipeline: boolean;
  api_scan: boolean;
  pr_guardrail: boolean;
}): Promise<ToolAssignment> {
  return jsonFetch<ToolAssignment>("/api/tools/assignments", { method: "PUT", body: JSON.stringify(a) });
}

/**
 * Executes a PR Guardrail scan against an open pull request.
 */
export function runPrGuardrailScan(targetId: number, prNumber: number): Promise<PrGuardrailScanResult> {
  return jsonFetch<PrGuardrailScanResult>(
    `/api/pr-guardrail/scan?target_id=${targetId}&pr_number=${prNumber}`,
    { method: "POST" },
  );
}

/**
 * Fetches PR Guardrail scan history for a specific target.
 */
export function getPrGuardrailLog(targetId: number): Promise<PrGuardrailLogEntry[]> {
  return jsonFetch<PrGuardrailLogEntry[]>(`/api/pr-guardrail/log?target_id=${targetId}`);
}

/**
 * Fetches organization-wide PR Guardrail scan log with statistics.
 */
export function getPrGuardrailOrgLog(): Promise<PrGuardrailOrgLog> {
  return jsonFetch<PrGuardrailOrgLog>("/api/pr-guardrail/log");
}

/**
 * Manually overrides a blocked PR Guardrail scan decision.
 */
export function overridePrGuardrail(prScanId: number, reason: string): Promise<PrGuardrailLogEntry> {
  return jsonFetch<PrGuardrailLogEntry>(`/api/pr-guardrail/${prScanId}/override`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

/**
 * Retrieves PR Guardrail scan metadata (PR number, URL).
 */
export function getPrGuardrailScan(
  prScanId: number,
): Promise<{ pr_number: number; pr_url: Nullable<string> }> {
  return jsonFetch<{ pr_number: number; pr_url: Nullable<string> }>(`/api/pr-guardrail/${prScanId}`);
}

/**
 * Retrieves the findings generated during a PR Guardrail scan.
 */
export function getPrGuardrailFindings(prScanId: number): Promise<PrGuardrailFinding[]> {
  return jsonFetch<PrGuardrailFinding[]>(`/api/pr-guardrail/${prScanId}/findings`);
}

/**
 * Submits a developer request to ignore a PR Guardrail finding.
 */
export function requestIgnoreFinding(findingId: number, reason: string): Promise<PrGuardrailFinding> {
  return jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/request-ignore`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

/**
 * Retrieves paginated pending ignore requests awaiting security review.
 */
export function getPendingIgnoreRequests(
  page = 1,
  pageSize = DEFAULT_PAGE_SIZE,
): Promise<PrGuardrailFindingPage> {
  return jsonFetch<PrGuardrailFindingPage>(
    `/api/pr-guardrail/ignore-requests/pending?page=${page}&page_size=${pageSize}`,
  );
}

/**
 * Retrieves paginated historical ignore request review decisions.
 */
export function getIgnoreRequestHistory(
  page = 1,
  pageSize = DEFAULT_PAGE_SIZE,
): Promise<PrGuardrailFindingPage> {
  return jsonFetch<PrGuardrailFindingPage>(
    `/api/pr-guardrail/ignore-requests/history?page=${page}&page_size=${pageSize}`,
  );
}

/**
 * Approves a finding ignore request.
 */
export function approveIgnore(findingId: number): Promise<PrGuardrailFinding> {
  return jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/approve-ignore`, { method: "POST" });
}

/**
 * Rejects a finding ignore request.
 */
export function rejectIgnore(findingId: number): Promise<PrGuardrailFinding> {
  return jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/reject-ignore`, { method: "POST" });
}

/**
 * Revokes a previously approved ignore request.
 */
export function revokeIgnore(findingId: number): Promise<PrGuardrailFinding> {
  return jsonFetch<PrGuardrailFinding>(`/api/pr-guardrail/findings/${findingId}/revoke-ignore`, { method: "POST" });
}
