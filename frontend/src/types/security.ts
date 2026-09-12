import type { RunStatus } from "./common";
import type { Nullable } from "@/std-lib";

/**
 * Supported Large Language Model / AI provider backends.
 */
export type AiProvider = "anthropic" | "openai_compatible";

/**
 * Configuration and provider status of the AI enrichment engine.
 */
export type AiStatus = {
  configured: boolean;
  provider: AiProvider;
};

/**
 * Historical record of an AI-assisted finding root cause analysis (GET /api/ai/recent).
 */
export type AiRecentAnalysis = {
  finding_id: number;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  cve_id: Nullable<string>;
  target_id: number;
  target_name: string;
  state: string;
  last_analyzed_at: string;
};

/**
 * Machine learning model or dataset dependency in an AI Bill of Materials.
 */
export type AiBomComponent = {
  id: number;
  name: string;
  component_type: "machine-learning-model" | "data";
  version: string;
  source: string;
  evidence: string;
  unpinned: boolean;
  first_seen: string;
  last_seen: string;
};

/**
 * Complete AI Bill of Materials view for a target repository.
 */
export type AiBomView = {
  target_id: number;
  target_name: string;
  branch: string;
  generated: boolean;
  summary: {
    models: number;
    datasets: number;
    unpinned: number;
    hosted_api_models: number;
  };
  components: AiBomComponent[];
};

/**
 * API route endpoint discovered via AST code analysis.
 */
export type Endpoint = {
  id: number;
  framework: string;
  method: string;
  route: string;
  file: string;
  line: number;
  is_new: boolean;
  first_seen: string;
  last_seen: string;
};

/**
 * Polling outcome of an API endpoint discovery task.
 */
export type DiscoveryRunResult = {
  run_id: number;
  target_id: number;
  status: RunStatus;
  count: number;
  new_count: number;
  error: string;
  started_at: string;
  completed_at: Nullable<string>;
  endpoints?: Endpoint[];
};

/**
 * Software Bill of Materials (SBOM) dependency component.
 */
export type SbomComponent = {
  id: number;
  name: string;
  version: string;
  package_type: string;
  purl: string;
  source?: string;
  is_new: boolean;
  first_seen: string;
  last_seen: string;
};

/**
 * Polling outcome of an SBOM generation task.
 */
export type SbomRunResult = {
  run_id: number;
  target_id: number;
  status: RunStatus;
  count: number;
  new_count: number;
  error: string;
  started_at: string;
  completed_at: Nullable<string>;
  components?: SbomComponent[];
};

/**
 * Export document formats supported for SBOM downloads.
 */
export type SbomExportFormat = "cyclonedx-json" | "spdx-json" | "csv" | "pdf";

/**
 * Outcome of checking an SBOM inventory against OSV.dev for newly reported malicious packages.
 */
export type MalwareCheckResult = {
  target_id: number;
  status: "clean" | "found" | "failed";
  malicious_count: number;
  findings_created: number;
};

/**
 * Result of syncing or uploading an external SBOM inventory.
 */
export type SbomImportResult = {
  target_id: number;
  count: number;
  new_count: number;
  malware?: Omit<MalwareCheckResult, "target_id">;
};

/**
 * Cross-target SBOM component entry for organization-level inventory.
 */
export type OrgSbomComponent = {
  name: string;
  version: string;
  purl: string;
  package_type: string;
  targets: { id: number; name: string }[];
};

/**
 * Aggregated organization-wide SBOM catalog.
 */
export type OrgSbomResult = {
  targets_with_sbom_count: number;
  total_targets_count: number;
  unique_component_count: number;
  components: OrgSbomComponent[];
};

/**
 * Types of policy rules governing PR blocking and rule suppression.
 */
export type PolicyRuleType = "block_severity" | "suppress_rule" | "suppress_license";

/**
 * Organization or workspace security policy rule.
 */
export type PolicyRule = {
  id: number;
  workspace_id: number;
  rule_type: PolicyRuleType;
  value: string;
  reason: string;
  created_by: string;
  created_at: string;
  active: boolean;
};

/**
 * Auto-learned false positive suppression rule generated from triage decisions.
 */
export type FalsePositiveRule = {
  id: number;
  workspace_id: number;
  rule_id: string;
  tool: string;
  file_path_pattern: Nullable<string>;
  source_finding_id: Nullable<number>;
  created_by: string;
  created_at: string;
  active: boolean;
  match_count: number;
  last_matched_at: Nullable<string>;
};

/**
 * Statistics on learned false positive suppressions in a workspace.
 */
export type FpRuleStats = {
  active_rules: number;
  total_matches: number;
};
