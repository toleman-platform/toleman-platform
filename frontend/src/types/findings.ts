/**
 * Security findings, triage states, queries, enrichment, and SLA rules.
 */

import type { Nullable } from "@/std-lib";

/**
 * Core security finding record identified across repositories and scanners.
 */
export type Finding = {
  id: number;
  target_id: number;
  tool: string;
  rule_id: string;
  title: string;
  description: string;
  file_path: string;
  line_start: Nullable<number>;
  line_end: Nullable<number>;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  priority_score: number;
  branch: string;
  state: string;
  cve_id: Nullable<string>;
  epss_score: Nullable<number>;
  kev_listed: boolean;
  first_seen: string;
  last_seen: string;
  /**
   * Resolved SLA days window (computed via group/severity inheritance).
   * Null when no SLA rule applies to this finding.
   */
  sla_days: Nullable<number>;
  /** True only when a real SLA applies and the finding is unmitigated past that window */
  sla_violated: boolean;
  /** Fixability classification from advisory metadata */
  fixability?: "fixable" | "no_known_fix" | "unknown";
  /** Vulnerability-type grouping (Code/SAST, Secret, OSS/SCA, License, IaC, AI/ML, ...) */
  category: string;
};

/**
 * Paginated response wrapper for lists of findings.
 */
export type FindingListResult = {
  items: Finding[];
  total: number;
};

/**
 * How a findings list is ordered. `exploitability` (priority score first) is
 * the default and is what the list has always done, so adding the control
 * does not reorder anyone's existing view. `blast_radius` is grouped-only:
 * "how many findings does this one decision close" has no meaning on a row
 * that is a single detection.
 */
export type FindingSort = "exploitability" | "severity" | "age" | "recent";
export type FindingGroupSort = FindingSort | "blast_radius";

/**
 * Filter query parameters for the /api/findings endpoint.
 */
export type FindingsQuery = {
  target_id?: number | number[];
  group_id?: number;
  state?: string | string[];
  severity?: string | string[];
  tool?: string | string[];
  category?: string;
  /** Categories to leave out. What the "Needs action" queue is built on. */
  exclude_category?: string[];
  fixability?: string | string[];
  resolved?: boolean;
  search?: string;
  /** Both halves of a group key, for expanding one grouped row into its members. */
  rule_id?: string | string[];
  /** Only findings first seen within this many days. Values below 1 are clamped to 1. */
  new_since_days?: number;
  sort?: FindingSort;
  page?: number;
  page_size?: number;
};

/**
 * Query parameters for the grouped findings list. Identical filters to
 * FindingsQuery, minus the ones that only make sense on a single detection
 * (`rule_id` selects a group's members, so it cannot also select groups).
 */
export type FindingGroupsQuery = Omit<FindingsQuery, "rule_id" | "sort"> & {
  sort?: FindingGroupSort;
};

/**
 * One decision, standing for every finding it would close.
 *
 * Identity is `(tool, rule_id)` — see backend/app/core/grouping.py for why
 * that key rather than a package name parsed out of a title. `grouped` is
 * false for categories deliberately never collapsed (Secrets, Malicious
 * Package), where the row is a single finding and offering an expander
 * would reveal only itself.
 */
export type FindingGroup = {
  tool: string;
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  grouped: boolean;
  finding_count: number;
  target_count: number;
  file_count: number;
  max_priority_score: number;
  oldest_first_seen: string;
  /** Newest first_seen in the group — what `sort=recent` orders by, matching the flat list. */
  newest_first_seen: string;
  newest_last_seen: string;
  max_epss: Nullable<number>;
  kev_count: number;
  /** The member the row's SLA and fixability are read off: worst severity, then oldest. */
  representative_id: number;
  representative_file_path: string;
  representative_target_id: number;
  sla_days: Nullable<number>;
  sla_violated: boolean;
  fixability: "fixable" | "no_known_fix" | "unknown";
};

export type FindingGroupListResult = {
  items: FindingGroup[];
  total: number;
  /** The group set hit the server ceiling, so `total` and `total_findings` are floors. */
  truncated: boolean;
  /** The count the flat list would have shown, so the UI can say "14 groups / 150 findings". */
  total_findings: number;
};

/**
 * Per-category finding counts query for category facets.
 */
export type CategoryFacetsQuery = Omit<FindingsQuery, "category" | "page" | "page_size">;

/**
 * Count breakdown for a single vulnerability category facet.
 */
export type CategoryFacet = {
  category: string;
  count: number;
};

/**
 * Automated fix recommendation and patch preview for a finding.
 */
export type FindingSuggestFix = {
  recommendation: string;
  strategy: Nullable<"ai" | "deterministic_sca">;
  diff: Nullable<string>;
  file_path: Nullable<string>;
  new_content: Nullable<string>;
  ref: Nullable<string>;
  explanation: Nullable<string>;
};

/**
 * Outcome of opening a pull request with an automated fix patch.
 */
export type RaiseFixPrResult = {
  pr_url: string;
  pr_number: number;
  branch: string;
};

/**
 * Remediation metadata for fix versions in open-source packages.
 */
export type FixVersionInfo = {
  package: Nullable<string>;
  ecosystem: Nullable<string>;
  fixed: string;
};

/**
 * CVE/CWE enrichment data sourced from NVD and OSV.dev (independent of AI).
 */
export type FindingEnrichment = {
  finding_id: number;
  cve_id: Nullable<string>;
  cve_description: Nullable<string>;
  cvss_score: Nullable<number>;
  cvss_vector: Nullable<string>;
  cwe_ids: Nullable<string[]>;
  references: Nullable<string[]>;
  fix_versions: Nullable<FixVersionInfo[]>;
  fetched_at: Nullable<string>;
};

/**
 * Service Level Agreement (SLA) policy rule defining remediation time windows.
 */
export type SlaRule = {
  id: number;
  workspace_id: number;
  group_id: Nullable<number>;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  days_to_fix: number;
  created_at: string;
};
