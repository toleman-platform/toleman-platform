import type { RunStatus } from "./common";

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
  pipeline_pr_url: string | null;
  is_ai_repo: boolean;
  is_ai_repo_signals: string;
  is_ai_repo_override: boolean | null;
  is_ai_repo_effective: boolean;
  enforcement_mode: EnforcementMode | null;
  effective_enforcement_mode?: EnforcementMode;
  enforcement_mode_source?: EnforcementModeSource;
  api_base_url: string | null;
  diff_scoped_pr_scans: boolean;
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
  pipeline_pr_url: string | null;
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
  | "already_integrated";

/**
 * Individual target status item in a bulk rollout batch.
 */
export type PipelineBatchItem = {
  target_id: number;
  target_name: string;
  repo_url: string | null;
  status: PipelineBatchItemStatus;
  error: string;
  pr_url: string | null;
  pr_number: number | null;
  completed_at: string | null;
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
  started_at: string;
  completed_at: string | null;
  items: PipelineBatchItem[];
  scope_label?: string;
  workflow_template_id?: number | null;
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
  target_count: number;
  enforcement_mode: EnforcementMode | null;
  effective_enforcement_mode?: EnforcementMode;
  enforcement_mode_source?: EnforcementModeSource;
  created_at: string;
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
