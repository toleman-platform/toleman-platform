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
};

/**
 * Paginated response wrapper for lists of findings.
 */
export type FindingListResult = {
  items: Finding[];
  total: number;
};

/**
 * Filter query parameters for the /api/findings endpoint.
 */
export type FindingsQuery = {
  target_id?: number;
  group_id?: number;
  state?: string;
  severity?: string;
  tool?: string;
  fixability?: string;
  search?: string;
  page?: number;
  page_size?: number;
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
