import type { RunStatus } from "./common";
import type { Nullable } from "@/std-lib";

// Issue #229: whether a *completed* run can be trusted to have checked what
// it claims. Orthogonal to status, which only says whether it finished.
// "suspect" means the platform refused to treat it as authoritative (it did
// not mitigate anything on the strength of it); "unknown" means nobody
// assessed the run, which every scan recorded before #229 carries and which
// is deliberately not a synonym for either of the other two.
export type ScanHealth = "healthy" | "suspect" | "unknown";

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
  // (#229) A completed scan with findings_count 0 is only a clean result if
  // the run was healthy; a poller that reads status alone would report a
  // clean repo for a scan that checked nothing.
  health: ScanHealth;
  health_note: string;
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
  // (#229) Tools whose most recent run against this target was not treated
  // as authoritative. Surfaced on the row itself because "last scan 4m ago ·
  // trivy" otherwise reads as reassurance for a run that checked nothing.
  suspect_tools: string[];
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
  health: ScanHealth;
  // Why the run was not trusted, and what was done about it. Non-empty
  // whenever health is "suspect".
  health_note: string;
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
export type IgnoreStatus = "none" | "requested" | "approved" | "rejected" | "revoked";

/**
 * Paginated response wrapper for PR Guardrail ignore requests.
 */
export type PrGuardrailFindingPage = {
  items: PrGuardrailFinding[];
  total: number;
};

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
  // Why a security reviewer turned down the ignore request -- only ever
  // set once ignore_status is "rejected"; null for every other status,
  // including rows rejected before this field existed (never an empty
  // string standing in for "no reason was given").
  reject_reason: Nullable<string>;
  // (#383) Which same-location group this finding belongs to, decided
  // server-side (see _grouped_findings_out) so the grouping rule lives in one
  // place rather than being reimplemented here and drifting from what the PR
  // comment renders for the same scan. Rows sharing a group_key are one line
  // flagged by two or more tools -- one problem, one fix -- and collapse into
  // a single expandable row.
  //
  // group_key is unique per group, NOT per location: the backend keeps some
  // same-location findings deliberately apart (one tool's own two rules on a
  // line; file-level findings with no line number), and those each get their
  // own key. group_size is how many members that group has, and is a ceiling
  // -- never merge more rows than it says.
  //
  // The group's tool list and severity are deliberately absent: they are pure
  // functions of the members and are derived at render time (groupFindings in
  // components/features/scans/pr-guardrail-log.tsx), so no row can be
  // labelled with another group's tools or badged at a severity none of its
  // members has.
  //
  // Optional because only GET /{pr_scan_id}/findings carries them: the
  // Approval Queue's pending/history endpoints list findings across scans,
  // where same-location grouping would be meaningless.
  group_key?: string;
  group_size?: number;
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
  blast_radius_files?: number;
  scope_reason?: string;
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

// Configurable scheduled scans (issue #306). Cadence used to be two
// hardcoded 24h entries in Celery's beat_schedule; it is per-workspace and
// per-target data now.
export type ScanScheduleType = "full_scan" | "api_scan";

// Where an effective value came from, so the UI can say "every 24h
// (workspace default)" instead of presenting an inherited cadence as this
// target's own decision. Same vocabulary as EnforcementModeSource, minus
// "group" (there is no group-level schedule).
export type ScanScheduleSource = "target" | "workspace" | "default";

/**
 * A single schedule row as the API renders it: the effective answer after
 * inheritance, plus the raw override stored at the scope being viewed.
 */
export type ScanScheduleView = {
  scan_type: ScanScheduleType;
  // The effective answer after inheritance...
  enabled: boolean;
  interval_hours: number;
  enabled_source: ScanScheduleSource;
  interval_source: ScanScheduleSource;
  // ...and the raw override stored at the scope being viewed. null means
  // "inheriting", which is NOT the same as false/0 and must stay
  // distinguishable: a select showing "Off" when the real answer is
  // "inherit, and the workspace says on" would be a lie in both directions.
  override_enabled: Nullable<boolean>;
  override_interval_hours: Nullable<number>;
  schedule_id: Nullable<number>;
  // null means this schedule has never fired. A fresh install genuinely
  // spends its first interval in that state, so it renders as "Never run"
  // rather than as a blank cell -- otherwise a scheduler that is quietly
  // not running looks exactly like one that simply has not come round yet.
  last_run_at: Nullable<string>;
  last_dispatched_count: Nullable<number>;
  // null when the schedule is disabled or has no stored row yet.
  next_run_at: Nullable<string>;
};

// Why a scheduled active API scan against this target would dispatch
// nothing. Computed by the same function the dispatcher itself refuses on,
// so the panel can never render a schedule as armed and healthy while the
// worker is quietly skipping it every cycle.
export type ApiScanBlockReason =
  | "target_inactive"
  | "tool_disabled"
  | "no_api_base_url"
  | "no_endpoints";

/**
 * Whether a scheduled active API scan against this target would actually
 * dispatch, and why not when it would not.
 */
export type ApiScanReadiness = {
  ready: boolean;
  reason: Nullable<ApiScanBlockReason>;
  detail: Nullable<string>;
};

/**
 * Target-scoped schedule view: every scan type, plus this target's API-scan
 * readiness.
 */
export type TargetScanSchedules = {
  target_id: number;
  workspace_id: number;
  api_scan_readiness: ApiScanReadiness;
  schedules: ScanScheduleView[];
};

/**
 * Workspace-scoped schedule view: the defaults every target inherits.
 */
export type WorkspaceScanSchedules = {
  workspace_id: number;
  // The one API-scan refusal a workspace-level view can answer with
  // certainty: nuclei's `api_scan` surface is workspace-scoped, so when it
  // is off, no target here will be probed no matter what the schedule says.
  // The other three reasons are per-target facts (see ApiScanReadiness) and
  // stay as a standing caveat under the panel rather than a false per-row
  // claim.
  api_scan_tool_enabled: boolean;
  schedules: ScanScheduleView[];
};

// Tri-state on the wire, matching the backend: omit a field to leave it
// alone, send null to go back to inheriting, send a value to decide at this
// level.
export type ScanSchedulePatch = {
  enabled?: Nullable<boolean>;
  interval_hours?: Nullable<number>;
};
