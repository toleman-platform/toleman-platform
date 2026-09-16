import type { RunStatus } from "./common";
import type { Nullable } from "@/std-lib";

/**
 * Embedded badge representing a Target's Group assignment (e.g. "PCI-scope", "Production").
 */
export type GroupBadge = {
  id: number;
  name: string;
  color: string;
};

/**
 * PR Guardrail enforcement modes.
 * - "block": Policy violations fail the PR commit status (blocks merge).
 * - "alert": Policy violations produce an informational warning status.
 * - "disabled": PR Guardrail scans do not run for this target.
 */
export type EnforcementMode = "block" | "alert" | "disabled";

/**
 * Provenance hierarchy for an effective enforcement mode resolution.
 * Resolves with most-specific-wins precedence: target -> group -> workspace -> default.
 */
export type EnforcementModeSource = "target" | "group" | "workspace" | "default";

/**
 * Status of the automatic GitHub Dependency Graph import on target creation.
 *
 * "skipped" (#273): the import declined to run because the target is
 * deactivated. Deliberately distinct from "unavailable" (GitHub refused to
 * answer) and "failed" -- nothing is broken, the inventory is simply frozen
 * at whatever was last imported.
 */
export type DependencySyncStatus = "pending" | "ok" | "unavailable" | "failed" | "skipped";

/**
 * Code repository or project asset monitored by the platform.
 */
export type Target = {
  id: number;
  workspace_id: number;
  name: string;
  repo_url: string;
  default_branch: string;
  label: string;
  criticality_weight: number;
  groups: GroupBadge[];
  pipeline_integrated: boolean;
  pipeline_pr_url: Nullable<string>;
  is_ai_repo: boolean;
  is_ai_repo_signals: string;
  is_ai_repo_override: Nullable<boolean>;
  is_ai_repo_effective: boolean;
  enforcement_mode: Nullable<EnforcementMode>;
  effective_enforcement_mode?: EnforcementMode;
  enforcement_mode_source?: EnforcementModeSource;
  api_base_url: Nullable<string>;
  diff_scoped_pr_scans: boolean;
  // (#247 follow-up) Auto-raise PRs for the Fix Plan's own dependency
  // upgrades, unattended, on the periodic sweep. Same plain per-target
  // on/off as diff_scoped_pr_scans above.
  auto_raise_fix_prs: boolean;
  client_cert_set?: boolean;
  client_key_set?: boolean;
  clone_proxy_url?: string;
  dependency_sync_status: Nullable<DependencySyncStatus>;
  dependency_sync_error: Nullable<string>;
  dependency_sync_at: Nullable<string>;
  dependency_component_count: Nullable<number>;
  // OSV malicious-package check status, separate from dependency_sync_*
  // above: that tracks the GitHub import, this tracks the OSV check
  // itself (also run by a plain re-check and by automatic SBOM
  // generation, neither of which touches dependency_sync_*). All null
  // means "never completed a check" -- render as unmeasured, not clean.
  // A failed attempt leaves these at whatever the last completed check
  // left them; see the backend model for why that's the honest choice.
  malware_last_checked_at: Nullable<string>;
  malware_last_check_status: Nullable<"clean" | "found">;
  malware_packages_checked: Nullable<number>;
  // (#273) Lifecycle. `is_active` is derived server-side from
  // deactivated_at, the same server-owns-the-precedence shape as
  // is_ai_repo_effective; never re-derive it here, and never render a
  // target as active because the timestamp field happened to be missing
  // from an older response. deactivated_at rides along for "deactivated
  // 3 days ago" display.
  //
  // A deactivated target is still scanned by nothing: on-demand, CI push
  // ingestion, PR Guardrail, active API scanning, the nightly baseline
  // refresh and pipeline rollout all refuse it server-side. The UI hiding
  // a button is a courtesy, not the enforcement.
  is_active: boolean;
  deactivated_at: Nullable<string>;
  // Soft-deleted targets never appear in any list response, so this is
  // effectively always null on anything the client receives; typed for
  // completeness rather than as something to branch on.
  deleted_at: Nullable<string>;
};

/**
 * Result of DELETE /api/targets/{id} (#273).
 *
 * Soft delete: the response reports what was deliberately NOT destroyed, so
 * the UI can say it out loud instead of leaving the operator to infer it.
 */
export type DeleteTargetResult = {
  id: number;
  deleted_at: string;
  retained_findings: number;
  retention: string;
};

/**
 * Generated GitHub Actions CI/CD workflow YAML for target scanning.
 */
export type PipelineWorkflow = {
  yaml: string;
  path: string;
  includes_gosec: boolean;
  languages: string[];
  detection_source: "scan_history" | "github_languages" | "default";
};

/**
 * Outcome of opening a pull request to integrate the scanner workflow into a target repo.
 */
export type PipelineIntegrateResult = {
  pipeline_integrated: boolean;
  pipeline_pr_url: Nullable<string>;
  pr_number: number;
  branch: string;
};

/**
 * Lifecycle state of an individual target within a bulk pipeline rollout batch.
 */
export type PipelineBatchItemStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "already_integrated"
  | "skipped_webhook_reachable";

/**
 * Individual target status item in a bulk rollout batch.
 */
export type PipelineBatchItem = {
  target_id: number;
  target_name: Nullable<string>;
  repo_url: Nullable<string>;
  status: PipelineBatchItemStatus;
  error: string;
  pr_url: Nullable<string>;
  pr_number: Nullable<number>;
  completed_at: Nullable<string>;
};

/**
 * Overall batch progress tracker for bulk CI/CD pipeline integration.
 */
export type PipelineIntegrationBatch = {
  batch_id: number;
  status: RunStatus;
  total: number;
  succeeded: number;
  failed: number;
  already_integrated: number;
  skipped_webhook_reachable: number;
  force: boolean;
  started_at: string;
  completed_at: Nullable<string>;
  items: PipelineBatchItem[];
  scope_label?: string;
  workflow_template_id?: Nullable<number>;
};

/**
 * Available scanner tool keys configurable in custom workflow steps.
 */
export const PIPELINE_WORKFLOW_TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"] as const;
export type PipelineWorkflowTool = (typeof PIPELINE_WORKFLOW_TOOLS)[number];

/**
 * Single scanner step configured in a PipelineWorkflowTemplate.
 */
export type PipelineWorkflowStep = {
  tool: PipelineWorkflowTool;
  enabled: boolean;
};

/**
 * Reusable CI/CD scanner template that can be rolled out across repositories.
 */
export type PipelineWorkflowTemplate = {
  id: number;
  workspace_id: number;
  name: string;
  steps: PipelineWorkflowStep[];
  created_by_user_id: number;
  created_at: string;
  updated_at: string;
};

/**
 * Organization-defined group/tag for segmenting targets within a workspace.
 */
export type Group = {
  id: number;
  workspace_id: number;
  name: string;
  color: string;
  created_at: string;
  // Issue #62: group-level enforcement-mode override, applied to every
  // target carrying this group (null = no override, inherit from workspace).
  enforcement_mode: Nullable<EnforcementMode>;
};

/**
 * Per-target open finding breakdown used in summary lists and repository sync inventories.
 */
export type TargetSummaryEntry = {
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
};

/**
 * Dictionary mapping target ID strings to TargetSummaryEntry.
 */
export type TargetSummary = Record<string, TargetSummaryEntry>;

