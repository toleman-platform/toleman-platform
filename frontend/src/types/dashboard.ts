/**
 * Dashboard metrics, configurable widget layout, and aggregated health scores.
 */

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
 */
export type SecurityScoreComponent = {
  score: number;
  weight: number;
  [key: string]: unknown;
};

/**
 * Composite 0-100 security health score, letter grade, and breakdown.
 */
export type SecurityScore = {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F" | null;
  target_count: number;
  weakest_component: "findings" | "sla" | "coverage" | "fp_rate" | "trend" | null;
  components: {
    findings: SecurityScoreComponent & {
      open_findings: number;
      weighted_severity_sum: number;
      avg_weighted_severity_per_target: number;
    };
    sla: SecurityScoreComponent & {
      with_sla: number;
      in_violation: number;
      compliant: number;
      note: string | null;
    };
    coverage: SecurityScoreComponent & {
      scanned_targets: number;
      total_targets: number;
      window_days: number;
    };
    fp_rate: SecurityScoreComponent & {
      false_positives: number;
      total_findings: number;
      fp_rate: number;
    };
    trend: SecurityScoreComponent & {
      direction: "improving" | "stable" | "worsening";
      current_weighted_sum: number;
      prior_weighted_sum: number;
      window_days: number;
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

export type KpiCardsData = {
  open: number;
  critical: number;
  high: number;
  mitigated: number;
  targets: number;
};

export type FindingsTrendData = {
  points: { date: string; open: number }[];
};

export type CveTimelineItem = {
  finding_id: number;
  cve_id: string;
  title: string;
  severity: string;
  state: string;
  target_id: number;
  target_name: string | null;
  first_seen: string;
  epss_score: number | null;
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

export type RecentFindingItem = {
  finding_id: number;
  title: string;
  severity: string;
  state: string;
  tool: string;
  target_id: number;
  target_name: string | null;
  file_path: string;
  first_seen: string;
  sla_days: number | null;
  sla_violated: boolean;
  fixability?: "fixable" | "no_known_fix" | "unknown";
};

export type RecentFindingsData = {
  items: RecentFindingItem[];
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
  eta_seconds: number | null;
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
  highest_new_severity: string | null;
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
  recent_findings: RecentFindingsData;
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
