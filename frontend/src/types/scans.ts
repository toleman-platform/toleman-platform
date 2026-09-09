import type { RunStatus } from "./common";
import type { Nullable } from "@/std-lib";

/**
 * Persisted scan run record capturing an individual scanner execution against a target.
 */
export type ScanRun = {
  scan_id: number;
  target_id: number;
  tool: string;
  branch: string;
  status: RunStatus;
  findings_count: number;
  started_at: string;
  completed_at: Nullable<string>;
  error_message: string;
  elapsed_seconds: number;
  eta_seconds: Nullable<number>;
};

/**
 * Scan run currently in-flight.
 */
export type ActiveScan = {
  scan_id: number;
  tool: string;
  branch: string;
  started_at: string;
  elapsed_seconds: number;
  eta_seconds: Nullable<number>;
};

/**
 * Active scans currently executing across targets, keyed by target ID string.
 */
export type ActiveScans = Record<string, ActiveScan[]>;

/**
 * Active PR Guardrail scan in progress, keyed by `${targetId}:${prNumber}`.
 */
export type ActivePrScan = {
  pr_scan_id: number;
  target_id: number;
  pr_number: number;
  branch: string;
  started_at: string;
};

/**
 * Active PR Guardrail scans dictionary.
 */
export type ActivePrScans = Record<string, ActivePrScan>;

/**
 * High-level summary of latest scanner activity per target.
 */
export type ScanSummaryEntry = {
  last_scan_at: Nullable<string>;
  tools: string[];
};

/**
 * Dictionary mapping target ID strings to their ScanSummaryEntry.
 */
export type ScanSummary = Record<string, ScanSummaryEntry>;

/**
 * Historical scan execution record for single-target history tabs.
 */
export type ScanHistoryEntry = {
  scan_id: number;
  tool: string;
  branch: string;
  status: string;
  started_at: string;
  completed_at: Nullable<string>;
  findings_count: number;
  error: string;
};

/**
 * Supported scanner tool metadata from the platform Tool Registry.
 */
export type ToolRegistryEntry = {
  tool: string;
  display_name: string;
  category: string;
  languages: string[];
  description: string;
  install_cmd: string;
  docs_url: string;
  integrated: boolean;
  installed: boolean;
  version: Nullable<string>;
  response_ms: Nullable<number>;
  checked_in: "api" | "worker";
  installable: boolean;
  bundled: boolean;
};

/**
 * Asynchronous job tracking the installation of an open-source scanner tool.
 */
export type ToolInstallRun = {
  run_id: number;
  tool: string;
  package: string;
  status: RunStatus;
  started_at: string;
  completed_at: Nullable<string>;
  installed_version: string;
  error: string;
  output_tail: string;
};

/**
 * Tool assignment matrix enabling/disabling a scanner across workflows.
 */
export type ToolAssignment = {
  tool: string;
  on_demand_scan: boolean;
  ci_pipeline: boolean;
  api_scan: boolean;
  pr_guardrail: boolean;
  is_default: boolean;
};

/**
 * Ephemeral finding item returned in a PR Guardrail scan response.
 */
export type PrGuardrailFindingSummary = {
  tool: string;
  rule_id: string;
  title: string;
  file_path: string;
  line_start: Nullable<number>;
  severity: string;
};

/**
 * Outcome verdict of a PR Guardrail scan execution.
 */
export type PrGuardrailScanResult = {
  pr_scan_id: number;
  status: "passed" | "blocked" | "error";
  new_findings_count: number;
  highest_new_severity: Nullable<string>;
  new_findings: PrGuardrailFindingSummary[];
};

/**
 * Approval status for developer ignore requests on PR Guardrail findings.
 */
export type IgnoreStatus = "none" | "requested" | "approved" | "rejected";

/**
 * Persisted PR Guardrail finding with ignore workflow tracking.
 */
export type PrGuardrailFinding = {
  id: number;
  pr_scan_id: number;
  tool: string;
  rule_id: string;
  title: string;
  file_path: string;
  line_start: Nullable<number>;
  severity: string;
  ignore_status: IgnoreStatus;
  ignore_requested_by: string;
  ignore_requested_reason: string;
  ignore_reviewed_by: string;
  ignore_reviewed_at: Nullable<string>;
};

/**
 * Audit log entry recording a PR Guardrail decision and commit status sync.
 */
export type PrGuardrailLogEntry = {
  id: number;
  pr_number: number;
  pr_title: string;
  branch: string;
  status: "running" | "passed" | "blocked" | "error" | "overridden";
  new_findings_count: number;
  highest_new_severity: Nullable<string>;
  new_endpoints_count: number;
  tools_run: string[];
  tools_failed: string[];
  tools_skipped?: string[];
  scan_scope?: "full" | "diff";
  files_scanned?: number;
  status_delivery_error: string;
  override_reason: string;
  created_at: string;
  completed_at: Nullable<string>;
  pr_url: Nullable<string>;
  target_id?: number;
  target_name?: Nullable<string>;
};

/**
 * Aggregate metrics for PR Guardrail evaluations across an organization.
 */
export type PrGuardrailOrgStats = {
  total: number;
  passed: number;
  blocked: number;
  overridden: number;
  error: number;
  running: number;
};

/**
 * Paginated or full org-level PR Guardrail log with summary stats.
 */
export type PrGuardrailOrgLog = {
  scans: PrGuardrailLogEntry[];
  stats: PrGuardrailOrgStats;
};
