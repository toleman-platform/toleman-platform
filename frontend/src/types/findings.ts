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
  /** The global workspace switcher's active workspace; omitted (or null) means every accessible workspace. */
  workspace_id?: number | null;
  state?: string | string[];
  severity?: string | string[];
  tool?: string | string[];
  category?: string;
  /** Categories to leave out. What the "Needs action" queue is built on. */
  exclude_category?: string[];
  fixability?: string | string[];
  /**
   * (#251) The owning target's metadata. Multi-select since #270, like every
   * other filter in the bar; a single value still works.
   */
  environment?: string | string[];
  owner?: string | string[];
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
 * FindingsQuery, with its own sort vocabulary.
 *
 * `rule_id` used to be excluded here on the reasoning that it selects a
 * group's *members*. Since the group key is `(tool, rule_id)`, filtering the
 * grouped list by it selects that group and nothing else -- which is what a
 * caller linking to one specific decision needs, and what `search` cannot
 * express, since search also matches title, file path, CVE and target name.
 */
export type FindingGroupsQuery = Omit<FindingsQuery, "sort"> & {
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
 * One option of one filter, and how many findings it would match.
 */
export type FacetCount = { value: string; count: number };

/**
 * (#270) Live per-value counts for every filter on the Findings page
 * (GET /api/findings/facets), so the filter bar reads as a summary of the
 * backlog ("Critical 12") instead of controls you have to operate to learn
 * anything. Takes the same query params as api.findings; each dimension's
 * counts are scoped by every OTHER active filter but not by its own, so
 * picking `environment=production` re-counts Critical/High for production
 * rather than blanking out the severities you haven't picked.
 *
 * Every dimension always lists its full option set, zeros included: "none
 * match right now" and "not a dimension" have to look different.
 */
export type FindingFacets = {
  severity: FacetCount[];
  state: FacetCount[];
  tool: FacetCount[];
  fixability: FacetCount[];
  environment: FacetCount[];
  owner: FacetCount[];
  category: FacetCount[];
  /**
   * The count for the complete filter set -- identical to api.findings()'
   * `total` for the same params, by construction on the backend.
   */
  total: number;
};

/**
 * Facets take the list's filters, never its paging: only the list has pages.
 * `rule_id` expands one grouped row into its members, which is not a filter
 * the bar offers either.
 */
export type FindingFacetsQuery = Omit<FindingsQuery, "page" | "page_size" | "rule_id" | "sort">;

/**
 * What the Findings page falls back to when the facets call fails: the same
 * option sets, from the plain per-dimension endpoints, with no counts. The
 * filter bar takes `facets: FindingFacets | null` and renders these instead
 * when it is null -- deliberately NOT an all-zeros FindingFacets, because
 * "0 findings match Critical" and "we could not count" are different claims
 * and only one of them is true in that situation.
 */
export type FindingFilterOptions = {
  tool: string[];
  environment: string[];
  owner: string[];
  category: CategoryFacet[];
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
 * (#247) One CVE that a package's recommended upgrade actually closes.
 * `title` is carried alongside the CVE/severity because this is the one
 * place a fix is described without the underlying Finding row in hand.
 */
export type RemediationFix = {
  cve_id: string;
  finding_id: number;
  severity: Finding["severity"];
  title: string;
};

/**
 * (#247) One CVE on the SAME package that the upgrade does NOT close --
 * no advisory offers it a fix at all. The backend does not send a `title`
 * here (see backend/app/core/remediation.py's second pass): only render
 * what it actually reported, never a fabricated label, so a missing title
 * cannot be papered over with a guess.
 */
export type RemediationUnresolved = {
  cve_id: string;
  finding_id: number;
  severity: Finding["severity"];
};

/**
 * (#247) One package upgrade recommendation from
 * GET /api/findings/remediations (backend/app/core/remediation.py's
 * group_remediations) -- the smallest set of version bumps that would close
 * the most open, CVE-bearing findings on a target, most findings-closed
 * first.
 *
 * Two properties that module's docstring calls out, both about overstating,
 * and both the reason this type exists rather than reusing a looser shape:
 *
 * - `upgrade_to` is the LOWEST version that clears every CVE in `fixes`,
 *   never the newest release. Never label it "latest" or "recommended" in
 *   the UI -- it is specifically the smallest jump the evidence supports,
 *   and a bigger one reads as a recommendation nobody asked for.
 * - `unresolved` is what this SAME upgrade leaves behind. Never hide it,
 *   never fold its length into `fixes_count`, and never render a summary
 *   like "upgrading fixes this package" when `unresolved` is non-empty --
 *   "fixes N of M findings" is the only claim the data supports.
 */
export type PackageRemediation = {
  package: string;
  ecosystem: Nullable<string>;
  upgrade_to: string;
  fixes: RemediationFix[];
  fixes_count: number;
  unresolved: RemediationUnresolved[];
  highest_severity: Finding["severity"];
  // (#247 follow-up) Only set by GET /api/findings/remediations/workspace,
  // the Findings page's cross-target aggregate -- a package fix is
  // inherently one-target-scoped (raising a PR needs a specific repo), so
  // the same package needing an upgrade on two targets is two rows here,
  // each tagged with which target it's for. Absent on the per-target Fix
  // Plan tab's own rows, where the target is already the page's context.
  target_id?: number;
  target_name?: string;
};

/**
 * (#247) How much has actually been looked up behind a fix plan.
 *
 * An empty `plans` array is the same value for two unrelated situations --
 * nothing has been enriched for this target's CVEs yet, and every advisory
 * was read and none names a fixed version -- and only the second is a
 * statement about fixes. Rendering the second for the first is the confident
 * negative `AGENTS.md` §1.4 forbids, so the empty state has to branch on
 * these counts rather than on `plans.length` alone.
 *
 * Every count is over *open findings carrying a CVE id*, the same population
 * the plans are built from, and each is a subset of `cve_findings`:
 *
 * - `enriched_findings` -- their CVE has an enrichment row. A row means a
 *   lookup happened, NOT that it returned anything: the backend caches a row
 *   even when both upstream sources fail.
 * - `findings_with_advisory` -- that row came from a real OSV record. This
 *   is the count that licenses the sentence "no fixed version is published";
 *   without it, zero fixes is silence rather than an answer.
 * - `findings_with_fix_data` -- that record names at least one fixed
 *   version. Zero here is exactly when `plans` is empty.
 */
export type RemediationCoverage = {
  cve_findings: number;
  distinct_cves: number;
  enriched_findings: number;
  findings_with_advisory: number;
  findings_with_fix_data: number;
};

/**
 * (#247) The response of GET /api/findings/remediations: the plans, and the
 * coverage they were computed from. The two are read together -- see
 * `RemediationCoverage` for why the plans alone cannot answer the empty
 * case honestly.
 *
 * `plans` is one page of the whole-target list (`page`/`page_size` params);
 * `total` is the WHOLE-target package count, not this page's length -- a
 * "N upgrades would close..." summary needs the whole-target number even
 * when only a page of them is on screen. `coverage` is unaffected by
 * paging: it is an honesty counter about the target, not a page stat.
 */
export type RemediationPlanResponse = {
  plans: PackageRemediation[];
  coverage: RemediationCoverage;
  total: number;
};

/**
 * (#247 follow-up) POST /api/findings/remediations/raise-pr's response:
 * the PR opened for one package's upgrade, covering every finding it
 * resolves in a single commit-and-open-PR call.
 */
export type RaisePackageFixPrResult = {
  pr_url: string;
  pr_number: number;
  branch: string;
};

/**
 * (#247 follow-up) One package's outcome within a RemediationPrBatch (the
 * async "Raise all" run) -- mirrors PipelineIntegrationBatchItem's shape.
 */
export type RemediationPrBatchItem = {
  package: string;
  status: "pending" | "running" | "succeeded" | "failed";
  error: string;
  pr_url: Nullable<string>;
  pr_number: Nullable<number>;
  completed_at: Nullable<string>;
};

/**
 * (#247 follow-up) GET /api/findings/remediations/raise-all-batches/{id}'s
 * response: the async "Raise all" run's live status, one item per package
 * in the plan at the time it was dispatched. `status` on the batch itself
 * follows the same PollableStatus shape lib/poll.ts's pollUntilSettled
 * expects ("running" | "completed" -- "failed" never appears at the batch
 * level, only per-item; a batch with every item failed still finishes
 * "completed", the same distinction PipelineIntegrationBatch draws).
 */
export type RemediationPrBatch = {
  batch_id: number;
  target_id: number;
  status: "running" | "completed";
  total: number;
  succeeded: number;
  failed: number;
  started_at: string;
  completed_at: Nullable<string>;
  items: RemediationPrBatchItem[];
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

// (#201) One signal slot of the risk-prioritisation engine, with this
// workspace's effective weight merged in. The backend always returns the
// full catalogue rather than just the stored overrides, so the baseline
// lives in exactly one place (app/core/scoring.py::BASELINE_WEIGHTS) and
// this client never has to keep a second copy of it in sync.
//
// `is_default`/`rule_id` are what separate "0.0 because that is the shipped
// baseline" from "0.0 because someone switched this signal off" -- identical
// numbers, and only the second one has anything to reset.
export type ScoringWeight = {
  signal: string;
  label: string;
  description: string;
  weight: number;
  baseline_weight: number;
  // Points this signal can contribute at weight 1.0; null for the two
  // multiplicative slots (severity, business criticality) whose
  // contribution has no fixed ceiling.
  max_points: Nullable<number>;
  // How the slot enters the score. "multiplier" scales a factor of the base
  // product, "points" adds up to max_points x weight, and "floor" raises the
  // score *to* max_points x weight -- so what a floor is worth depends on
  // where the finding already sat, and describing KEV as "up to 900 pts"
  // would be false for every finding not already near the bottom.
  contribution: "multiplier" | "points" | "floor";
  is_default: boolean;
  rule_id: Nullable<number>;
  workspace_id: number;
};

/**
 * The full effective risk-scoring configuration for one workspace.
 */
export type ScoringWeights = {
  workspace_id: number;
  max_score: number;
  signals: ScoringWeight[];
};

// (#201) One line of a finding's score explanation.
//
// `established` is load-bearing and must not be collapsed into `points`.
// Zero points means either "this signal applied and contributed nothing"
// (EPSS below the threshold) or "this signal was never established" (no CVE
// to look up). Only the first is a statement about the finding; rendering
// them identically is the same mistake #246 exists to prevent.
export type FindingScoreSignal = {
  signal: string;
  label: string;
  weight: number;
  points: number;
  established: boolean;
  detail: string;
};

// (#201) `stored_score` is the number on the Finding row -- what every list,
// filter and SLA check sorts by. `score` is what the current signals and
// weights produce right now. They diverge legitimately (a weight changed, or
// CVE enrichment ran after ingestion), and `stale` says so rather than the
// UI quietly showing whichever one it prefers.
export type FindingScoreBreakdown = {
  finding_id: number;
  stored_score: number;
  score: number;
  stale: boolean;
  base_points: number;
  max_score: number;
  capped: boolean;
  signals: FindingScoreSignal[];
};
