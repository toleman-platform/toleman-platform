/**
 * Dashboard metrics, configurable widget layout, and aggregated health scores.
 */

import type { Nullable } from "@/std-lib";

/**
 * High-level counts of total, open, and mitigated findings across an organization or scope.
 */
export type Summary = {
  total: number;
  open: number;
  mitigated: number;
};

/**
 * Individual score dimension within the composite security score.
 *
 * `measurable` is false when this platform had no data to compute the
 * dimension from. Such a component carries `score: null` and is left out of
 * the composite entirely (the remaining weights are renormalised server
 * side) rather than counted as a zero, which would be indistinguishable
 * from a measured worst case.
 */
export type SecurityScoreComponent = {
  score: Nullable<number>;
  weight: number;
  measurable: boolean;
  [key: string]: unknown;
};

/**
 * Composite 0-100 security health score, letter grade, and breakdown.
 *
 * `score` is null only if no dimension at all could be measured; with no
 * targets in scope it is 0 and `grade` is null.
 */
export type SecurityScore = {
  score: Nullable<number>;
  grade: Nullable<"A" | "B" | "C" | "D" | "F">;
  target_count: number;
  weakest_component: Nullable<"findings" | "sla" | "coverage" | "fp_rate" | "trend">;
  components: {
    findings: SecurityScoreComponent & {
      /** Every open default-branch finding, licence rows included. */
      open_findings: number;
      /** The subset that carries weight in this dimension's score. */
      open_vulnerabilities: number;
      license_findings_excluded: number;
      weighted_severity_sum: number;
      avg_weighted_severity_per_target: number;
    };
    sla: SecurityScoreComponent & {
      with_sla: number;
      in_violation: number;
      compliant: number;
      note: Nullable<string>;
    };
    // (#273) `total_targets` is the *scannable* count: deactivated targets
    // are excluded from both sides of the coverage fraction, since nothing
    // can scan them and leaving them in the denominator would make the
    // score decay for a repo that was switched off on purpose.
    // `deactivated_targets` says how many were left out, so "12 of 15"
    // against a target list of 20 is reconcilable rather than mysterious.
    coverage: SecurityScoreComponent & {
      scanned_targets: number;
      total_targets: number;
      deactivated_targets: number;
      window_days: number;
      note: Nullable<string>;
    };
    fp_rate: SecurityScoreComponent & {
      false_positives: number;
      total_findings: number;
      fp_rate: number;
    };
    // `direction` is "unknown" and `prior_weighted_sum` null when there is
    // no observation from `window_days` ago to compare against; `note` then
    // says so in the server's own words.
    trend: SecurityScoreComponent & {
      direction: "improving" | "stable" | "worsening" | "unknown";
      current_weighted_sum: number;
      prior_weighted_sum: Nullable<number>;
      window_days: number;
      note: Nullable<string>;
    };
  };
};

/**
 * Available widget identifiers supported in the customizable dashboard layout.
 */
export type WidgetId =
  | "kpi_cards"
  | "findings_trend"
  | "cve_timeline"
  | "sla_compliance"
  | "top_risky_repos"
  | "recent_findings"
  | "security_score"
  | "fp_auto_suppressions"
  | "live_scan_activity"
  | "ai_ml_risk"
  | "guardrail_activity";

/**
 * Widget definition entry in the dashboard catalog.
 */
export type WidgetCatalogEntry = {
  widget_id: WidgetId;
  name: string;
  description: string;
};

/**
 * Configured widget placement within a user's dashboard layout.
 */
export type LayoutWidget = {
  id: string;
  widget_id: WidgetId;
  config: Record<string, unknown>;
};

/**
 * Persisted layout output containing all active widgets.
 */
export type DashboardLayoutOut = {
  widgets: LayoutWidget[];
};

/**
 * Counts behind the KPI cards. `open`, `critical`, `high` and `mitigated`
 * count vulnerabilities only; licence-compliance findings are reported
 * separately as `license_open` so the two are never added together.
 */
export type KpiCardsData = {
  open: number;
  critical: number;
  high: number;
  mitigated: number;
  targets: number;
  /** Optional: absent from a payload served by a backend predating it. */
  license_open?: number;
};

export type FindingsTrendData = {
  points: { date: string; open: number; mitigated: number }[];
};

export type CveTimelineItem = {
  finding_id: number;
  cve_id: string;
  title: string;
  severity: string;
  state: string;
  target_id: number;
  target_name: Nullable<string>;
  first_seen: string;
  epss_score: Nullable<number>;
  kev_listed: boolean;
};

export type CveTimelineData = {
  items: CveTimelineItem[];
};

export type SlaComplianceData = {
  with_sla: number;
  in_violation: number;
  compliant: number;
};

export type TopRiskyRepoItem = {
  target_id: number;
  target_name: string;
  critical: number;
  high: number;
  priority_score_sum: number;
};

export type TopRiskyReposData = {
  items: TopRiskyRepoItem[];
};

/**
 * One row of the "Needs Action Queue" widget: a single decision (a
 * `(tool, rule_id)` group, or an ungrouped Secrets/Malicious Package
 * finding standing for itself -- `grouped` tells which), never a finding
 * already past triage. Mirrors `FindingGroupOut` on the Findings page
 * (GET /api/findings/groups) for the fields both share; `state` is this
 * widget's own addition -- always "Open" or "Reopened" (the resolver's
 * query already excludes every resolved state), read off the single
 * representative member rather than synthesised across the group, same as
 * `sla_days`/`sla_violated` below.
 */
export type NeedsActionItem = {
  tool: string;
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  state: string;
  grouped: boolean;
  finding_count: number;
  representative_id: number;
  representative_target_id: number;
  target_name: Nullable<string>;
  representative_file_path: string;
  first_seen: string;
  sla_days: Nullable<number>;
  sla_violated: boolean;
};

export type NeedsActionQueueData = {
  items: NeedsActionItem[];
};

export type FpAutoSuppressionsData = {
  count: number;
  since: string;
};

export type LiveScanActivityItem = {
  scan_id: number;
  tool: string;
  target_id: number;
  target_name: string;
  branch: string;
  started_at: string;
  elapsed_seconds: number;
  eta_seconds: Nullable<number>;
};

export type LiveScanActivityData = {
  count: number;
  items: LiveScanActivityItem[];
};

export type AiMlRiskData = {
  ai_repo_count: number;
  modelscan_open: number;
  semgrep_llm_open: number;
};

export type GuardrailActivityItem = {
  pr_scan_id: number;
  target_id: number;
  target_name: string;
  pr_number: number;
  pr_title: string;
  status: string;
  new_findings_count: number;
  highest_new_severity: Nullable<string>;
  created_at: string;
};

export type GuardrailActivityData = {
  pending_approvals: number;
  items: GuardrailActivityItem[];
};

/**
 * Mapping between WidgetId and its concrete payload data type.
 */
export type WidgetDataMap = {
  kpi_cards: KpiCardsData;
  findings_trend: FindingsTrendData;
  cve_timeline: CveTimelineData;
  sla_compliance: SlaComplianceData;
  top_risky_repos: TopRiskyReposData;
  // Catalog id kept as `recent_findings` for backward compatibility with
  // already-saved DashboardLayout rows; the payload is the Needs Action
  // Queue now (see NeedsActionQueueData and app.core.widgets.
  // resolve_needs_action_queue's docstring for why).
  recent_findings: NeedsActionQueueData;
  security_score: SecurityScore;
  fp_auto_suppressions: FpAutoSuppressionsData;
  live_scan_activity: LiveScanActivityData;
  ai_ml_risk: AiMlRiskData;
  guardrail_activity: GuardrailActivityData;
};

/**
 * Single widget data response payload or error envelope.
 */
export type WidgetDataEntry =
  | { widget_id: WidgetId; data: WidgetDataMap[WidgetId]; error?: undefined }
  | { widget_id: WidgetId; data?: undefined; error: string };

/**
 * Batched multi-widget data response.
 */
export type WidgetDataResponse = {
  widgets: Record<string, WidgetDataEntry>;
};
