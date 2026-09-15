"use client";

import Link from "next/link";
import { useId, useState } from "react";
import {
  ShieldAlert,
  GitBranch,
  CheckCircle2,
  Timer,
  Activity,
  Bug,
  AlertTriangle,
  ListChecks,
  Gauge,
  TrendingDown,
  TrendingUp,
  Minus,
  ShieldCheck,
  Inbox,
  AlertOctagon,
  Loader2,
  Bot,
  GitPullRequest,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { TruncateTooltip } from "@/components/ui/truncate-tooltip";
import { ProgressBar } from "@/components/ui/progress-bar";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { SeverityChip } from "@/components/ui/severity-chip";
// Read-only reuse of the Findings page's own triage-state palette: a
// finding's `state` is never "Critical"/"High" etc., so it needs its own
// color mapping rather than SeverityChip's, and finding-row.tsx already
// established what that mapping should look like -- a second,
// independently-invented one here is how "Reopened" ends up meaning a
// different color on two pages that both claim to show it.
import { STATE_COLOR } from "@/lib/severity";
import { Timestamp } from "@/components/ui/timestamp";
import { LOG_STATUS_COLOR } from "@/components/features/scans/pr-guardrail-log";
import { FindingsTrendLine } from "@/components/charts/findings-trend-line";
import { SecurityScoreGauge } from "@/components/charts/security-score-gauge";
import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import type {
  WidgetId,
  WidgetDataEntry,
  KpiCardsData,
  FindingsTrendData,
  CveTimelineData,
  SlaComplianceData,
  TopRiskyReposData,
  NeedsActionQueueData,
  SecurityScore,
  FpAutoSuppressionsData,
  LiveScanActivityData,
  AiMlRiskData,
  GuardrailActivityData,
  Group,
  Target,
} from "@/lib/api";

// Issue #69: the concrete render for each widget type in the catalog,
// deliberately one component per real widget, not a generic chart
// interpreter. `icon`/`label` here drive both the "Add Widget" picker and
// the WidgetShell header; `render` consumes exactly the shape returned by
// that widget's app.core.widgets resolver on the backend.
export const WIDGET_META: Record<WidgetId, { label: string; icon: React.ElementType; colSpanClass?: string }> = {
  security_score: { label: "Security Score", icon: Gauge, colSpanClass: "lg:col-span-3" },
  kpi_cards: { label: "Security Posture", icon: ShieldAlert, colSpanClass: "lg:col-span-3" },
  sla_compliance: { label: "SLA Compliance", icon: Timer, colSpanClass: "lg:col-span-3" },
  findings_trend: { label: "Findings Over Time", icon: Activity, colSpanClass: "lg:col-span-2" },
  top_risky_repos: { label: "Top Risky Repos", icon: GitBranch },
  cve_timeline: { label: "CVE Timeline", icon: Bug, colSpanClass: "lg:col-span-2" },
  // Catalog id kept as `recent_findings` for backward compatibility with
  // already-saved DashboardLayout rows; label/icon/render below describe
  // what it actually is now (see app.core.widgets.resolve_needs_action_queue's
  // docstring for why this stopped being a plain recent-findings feed).
  recent_findings: { label: "Needs Action Queue", icon: ListChecks },
  fp_auto_suppressions: { label: "Auto-Suppressed Findings", icon: ShieldCheck },
  live_scan_activity: { label: "Live Scan Activity", icon: Loader2 },
  ai_ml_risk: { label: "AI/ML Risk", icon: Bot },
  guardrail_activity: { label: "Guardrail Activity", icon: GitPullRequest, colSpanClass: "lg:col-span-2" },
};

// Widget-scoped, compact variants of the shared empty/error patterns
// (src/components/ui/empty-state.tsx, error-state.tsx); widgets need
// inline JSX (a <Link> to the admin tab that fixes the empty state) inside
// the description, which the shared components' string-only `description`
// prop doesn't support, so these stay local but follow the same
// icon + copy shape for visual consistency across the dashboard.
function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-destructive">
      <AlertOctagon className="h-4 w-4 shrink-0" />
      <span>Couldn&apos;t load widget: {message}</span>
    </div>
  );
}

function EmptyState({ children, icon: Icon = Inbox }: { children: React.ReactNode; icon?: React.ElementType }) {
  return (
    <div className="flex flex-col items-center gap-2 px-2 py-6 text-center">
      <Icon className="h-5 w-5 text-muted-foreground" />
      <p className="max-w-xs text-sm text-muted-foreground">{children}</p>
    </div>
  );
}

function KpiCardsWidget({ data }: { data: KpiCardsData }) {
  const items = [
    // Label unified to "Findings" (#116); was "Open Vulnerabilities" while
    // the sidebar nav said "Vulnerabilities" and the page header said
    // "Findings"; all three now agree on one term.
    {
      icon: ShieldAlert,
      iconClass: "bg-destructive/10 text-destructive",
      value: data.open,
      label: "Open Findings",
      href: "/findings?state=Open",
      tone: "critical" as const,
    },
    {
      icon: AlertTriangle,
      iconClass: "bg-chart-3/10 text-chart-3",
      value: data.critical,
      label: "Critical Issues",
      href: "/findings?severity=Critical&state=Open",
      tone: "attention" as const,
    },
    {
      icon: GitBranch,
      iconClass: "bg-primary/10 text-accent-strong",
      value: data.targets,
      label: "Targets Onboarded",
      href: "/targets",
      tone: "default" as const,
    },
    {
      icon: CheckCircle2,
      iconClass: "bg-chart-5/10 text-chart-5",
      value: data.mitigated,
      label: "Mitigated",
      href: "/findings?state=Mitigated",
      tone: "positive" as const,
    },
  ];

  return (
    <StatGrid columns={4}>
      {items.map((it) => (
        <StatCard
          key={it.label}
          label={it.label}
          value={it.value}
          icon={it.icon}
          iconClass={it.iconClass}
          href={it.href}
          tone={it.tone}
        />
      ))}
    </StatGrid>
  );
}

function SlaComplianceWidget({ data }: { data: SlaComplianceData }) {
  if (data.with_sla === 0) {
    return (
      <EmptyState>
        No SLA rules configured yet. Set days-to-fix targets per severity/group on the{" "}
        <Link href="/admin" className="text-accent-strong underline">
          Admin &rsaquo; SLA Rules
        </Link>{" "}
        tab.
      </EmptyState>
    );
  }
  const total = data.with_sla;
  const compliantPct = total > 0 ? Math.round((data.compliant / total) * 100) : 100;
  const violationPct = total > 0 ? 100 - compliantPct : 0;

  return (
    <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div className="flex flex-wrap items-center gap-6">
        <div>
          <p className="text-2xl font-bold text-foreground">{data.with_sla}</p>
          <p className="text-xs text-muted-foreground">Open findings with an SLA</p>
        </div>
        <Link
          href="/findings?sla_violated=true&state=Open"
          className="group rounded-md px-2 py-1 transition-colors hover:bg-accent/40"
        >
          <p className={`text-2xl font-bold ${data.in_violation > 0 ? "text-destructive" : "text-foreground"}`}>
            {data.in_violation}
          </p>
          <p className="text-xs text-muted-foreground group-hover:underline">In violation &rarr;</p>
        </Link>
        <div>
          <p className="text-2xl font-bold text-chart-5">{data.compliant}</p>
          <p className="text-xs text-muted-foreground">Within SLA</p>
        </div>
      </div>

      <div className="flex min-w-[220px] flex-col gap-1.5 sm:min-w-[280px]">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-foreground">SLA Health Rate</span>
          <span className={`font-semibold ${compliantPct >= 80 ? "text-chart-5" : compliantPct >= 50 ? "text-chart-3" : "text-destructive"}`}>
            {compliantPct}%
          </span>
        </div>
        <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-secondary">
          <div
            className="bg-chart-5 transition-all duration-500"
            style={{ width: `${compliantPct}%` }}
            title={`Within SLA: ${data.compliant} (${compliantPct}%)`}
          />
          <div
            className="bg-destructive transition-all duration-500"
            style={{ width: `${violationPct}%` }}
            title={`In Violation: ${data.in_violation} (${violationPct}%)`}
          />
        </div>
        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
          <span>{data.compliant} within SLA</span>
          <span>{data.in_violation} violated</span>
        </div>
      </div>
    </div>
  );
}

function FpAutoSuppressionsWidget({ data }: { data: FpAutoSuppressionsData }) {
  if (data.count === 0) {
    return (
      <EmptyState>
        No findings auto-suppressed since <Timestamp value={data.since} mode="date" />. Rules are learned when a
        finding is triaged{" "}
        &quot;False Positive&quot;, manage them on the{" "}
        <Link href="/admin" className="text-accent-strong underline">
          Admin &rsaquo; False Positive Rules
        </Link>{" "}
        tab.
      </EmptyState>
    );
  }
  return (
    <div className="flex items-center gap-6">
      <div>
        <p className="text-2xl font-bold text-foreground">{data.count}</p>
        <p className="text-xs text-muted-foreground">
          Auto-suppressed since <Timestamp value={data.since} mode="date" />
        </p>
      </div>
    </div>
  );
}

function FindingsTrendWidget({ data }: { data: FindingsTrendData }) {
  return <FindingsTrendLine data={data} />;
}

// Issue #224: surfaces GET /api/scans/active's data (previously only
// visible on the Scans page and each target's own detail page) directly on
// the dashboard; "is anything running right now" is a question people
// otherwise had to go looking for.
function LiveScanActivityWidget({ data }: { data: LiveScanActivityData }) {
  if (data.items.length === 0) return <EmptyState icon={Loader2}>No scans running right now.</EmptyState>;
  return (
    <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
      {data.items.map((s) => (
        <Link
          key={s.scan_id}
          href={`/targets/${s.target_id}`}
          className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2 hover:bg-accent/40"
        >
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-accent-strong" aria-hidden="true" />
              <span className="truncate text-sm text-foreground">{s.target_name}</span>
              <Badge variant="outline" className="shrink-0 text-[10px]">
                {s.tool}
              </Badge>
            </div>
            <p className="mt-0.5 truncate text-xs text-muted-foreground">
              {s.elapsed_seconds}s elapsed{s.eta_seconds ? ` · ~${s.eta_seconds}s total` : ""}
            </p>
          </div>
        </Link>
      ))}
      {data.count > data.items.length && (
        <p className="px-1 text-xs text-muted-foreground">+{data.count - data.items.length} more running</p>
      )}
    </div>
  );
}

// Issue #224: AI-repo detection, ModelScan and the LLM ruleset had no
// dashboard-level presence; an org running them had to already know to
// look at the dedicated AI Security page (or filter Findings by tool name)
// to tell whether either scanner had found anything.
function AiMlRiskWidget({ data }: { data: AiMlRiskData }) {
  if (data.ai_repo_count === 0) {
    return (
      <EmptyState icon={Bot}>
        No AI/ML repos detected yet. A target is flagged automatically from its dependency manifests, or set
        manually on its Settings tab.
      </EmptyState>
    );
  }
  const totalOpen = data.modelscan_open + data.semgrep_llm_open;
  return (
    <Link href="/ai-security" className="flex items-center gap-6 rounded-md px-1 py-1 hover:bg-accent/40">
      <div>
        <p className="text-2xl font-bold text-foreground">{data.ai_repo_count}</p>
        <p className="text-xs text-muted-foreground">AI/ML repos</p>
      </div>
      <div>
        <p className={`text-2xl font-bold ${data.modelscan_open > 0 ? "text-chart-3" : "text-foreground"}`}>
          {data.modelscan_open}
        </p>
        <p className="text-xs text-muted-foreground">ModelScan open</p>
      </div>
      <div>
        <p className={`text-2xl font-bold ${data.semgrep_llm_open > 0 ? "text-chart-3" : "text-foreground"}`}>
          {data.semgrep_llm_open}
        </p>
        <p className="text-xs text-muted-foreground">LLM ruleset open</p>
      </div>
      {totalOpen === 0 && <p className="text-xs text-muted-foreground">No findings from either scanner.</p>}
    </Link>
  );
}

// Issue #224: recent PR Guardrail decisions plus the Approval Queue's
// pending count, reusing the exact same status colors as the full PR
// Guardrail log (pr-guardrail-log.tsx) so a "blocked" pill reads the same
// wherever it appears.
function GuardrailActivityWidget({ data }: { data: GuardrailActivityData }) {
  return (
    <div className="flex flex-col gap-3">
      {data.pending_approvals > 0 && (
        <Link
          href="/approval-queue"
          className="flex items-center justify-between rounded-md border border-chart-3/20 bg-chart-3/10 px-3 py-2 text-sm text-chart-3 hover:bg-chart-3/20"
        >
          <span>
            {data.pending_approvals} finding{data.pending_approvals === 1 ? "" : "s"} pending security review
          </span>
          <span className="text-xs underline">Review</span>
        </Link>
      )}
      {data.items.length === 0 ? (
        <EmptyState icon={GitPullRequest}>No PR Guardrail scans yet.</EmptyState>
      ) : (
        <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
          {data.items.map((s) => (
            <Link
              key={s.pr_scan_id}
              href={`/targets/${s.target_id}?tab=vulnerabilities`}
              className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2 hover:bg-accent/40"
            >
              <div className="min-w-0">
                <p className="truncate text-sm text-foreground">
                  #{s.pr_number} {s.pr_title || "(untitled PR)"}
                </p>
                <p className="truncate text-xs text-muted-foreground">
                  {s.target_name}
                  {s.new_findings_count > 0 && ` · ${s.new_findings_count} new finding${s.new_findings_count === 1 ? "" : "s"}`}
                </p>
              </div>
              <Badge variant="outline" className={`shrink-0 ${LOG_STATUS_COLOR[s.status] ?? "text-muted-foreground"}`}>
                {s.status}
              </Badge>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function TopRiskyReposWidget({ data }: { data: TopRiskyReposData }) {
  if (data.items.length === 0) return <EmptyState>No open findings yet.</EmptyState>;
  // (#250) The counts are the actionable part of this row, so they link
  // where the count came from (that target's open findings at that
  // severity) rather than dumping the reader on the target overview to
  // re-apply the filter by hand. The row is a div, not a Link, because a
  // link inside a link is invalid and the browser resolves it unpredictably.
  return (
    <div className="flex flex-col gap-2">
      {data.items.map((r) => {
        const totalRisky = r.critical + r.high;
        const critPct = totalRisky > 0 ? (r.critical / totalRisky) * 100 : 0;
        const highPct = totalRisky > 0 ? (r.high / totalRisky) * 100 : 0;

        return (
          <div key={r.target_id} className="group flex items-center justify-between gap-3 rounded-md px-2 py-1.5 transition-colors hover:bg-accent/40">
            <div className="flex min-w-0 flex-1 flex-col">
              <Link href={`/targets/${r.target_id}`} className="min-w-0 hover:underline">
                <TruncateTooltip
                  text={r.target_name}
                  className="text-sm font-medium text-foreground"
                />
              </Link>
              {totalRisky > 0 && (
                <div className="mt-1 flex h-1 w-24 overflow-hidden rounded-full bg-secondary">
                  <div className="bg-destructive" style={{ width: `${critPct}%` }} />
                  <div className="bg-chart-3" style={{ width: `${highPct}%` }} />
                </div>
              )}
            </div>
            <div className="flex shrink-0 gap-1.5">
              {r.critical > 0 && (
                <Link
                  href={`/findings?target_id=${r.target_id}&severity=Critical&state=Open`}
                  aria-label={`View ${r.critical} open Critical findings in ${r.target_name}`}
                >
                  <SeverityChip severity="Critical" count={r.critical} size="sm" className="hover:brightness-110 font-semibold" />
                </Link>
              )}
              {r.high > 0 && (
                <Link
                  href={`/findings?target_id=${r.target_id}&severity=High&state=Open`}
                  aria-label={`View ${r.high} open High findings in ${r.target_name}`}
                >
                  <SeverityChip severity="High" count={r.high} size="sm" className="hover:brightness-110 font-semibold" />
                </Link>
              )}
              {r.critical === 0 && r.high === 0 && <span className="text-xs text-muted-foreground">No critical/high open</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function CveTimelineWidget({ data }: { data: CveTimelineData }) {
  if (data.items.length === 0) return <EmptyState>No CVE findings yet.</EmptyState>;
  return (
    <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
      {data.items.map((item) => (
        <Link
          key={item.finding_id}
          href={`/findings?search=${encodeURIComponent(item.cve_id)}&target_id=${item.target_id}`}
          className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2 hover:bg-accent/40"
        >
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-accent-strong">{item.cve_id}</span>
              {item.kev_listed && <Badge variant="outline" className="border-destructive/40 bg-destructive/20 text-destructive">KEV</Badge>}
            </div>
            <p className="truncate text-sm text-foreground">{item.title}</p>
            <p className="text-xs text-muted-foreground">
              {item.target_name ?? `target #${item.target_id}`} &middot; <Timestamp value={item.first_seen} mode="date" />
            </p>
          </div>
          <SeverityChip severity={item.severity} size="sm" />
        </Link>
      ))}
    </div>
  );
}

function NeedsActionQueueWidget({ data }: { data: NeedsActionQueueData }) {
  // A real zero here means the Needs Action queue is genuinely empty --
  // the good outcome, not a missing-data state -- so this reads as an
  // all-clear rather than the generic "No findings yet." the old
  // Recent-Findings feed used, which read the same whether nothing had
  // been scanned yet or everything really was handled.
  if (data.items.length === 0) {
    return <EmptyState icon={CheckCircle2}>Nothing needs action right now.</EmptyState>;
  }
  return (
    <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
      {data.items.map((item) => (
        <Link
          // `representative_id` has to be part of this key, not just
          // `tool:rule_id`: two ungrouped Secrets findings (each its own
          // row -- see app.core.grouping's UNGROUPED_CATEGORIES) can share
          // one gitleaks rule, and `tool:rule_id` alone would collide them
          // into the same React key.
          key={`${item.tool}:${item.rule_id}:${item.representative_id}`}
          // `tool` + `rule_id` is the group key (backend/app/core/grouping.py),
          // so this lands on exactly this decision and nothing else -- not a
          // member's own detail page, since a grouped row stands for one
          // decision rather than one detection. Deliberately not `search`:
          // that matches title, file path, CVE and target name too, so a rule
          // id quoted inside an unrelated finding's title came along with it.
          href={`/findings?tool=${encodeURIComponent(item.tool)}&rule_id=${encodeURIComponent(item.rule_id)}&queue=action`}
          className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2 hover:bg-accent/40"
        >
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-1.5">
              <TruncateTooltip
                text={item.title}
                subtext={item.representative_file_path}
                className="text-sm text-foreground"
              />
              {/* A group's count of how many findings this one decision
                  closes (issue #119's four-identical-rows complaint, this
                  time collapsed on purpose instead of hidden by accident). */}
              {item.finding_count > 1 && (
                <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[10px] text-muted-foreground">
                  &times;{item.finding_count}
                </Badge>
              )}
            </div>
            <p className="truncate text-xs text-muted-foreground">
              {item.target_name ?? `target #${item.representative_target_id}`} &middot; {item.tool} &middot;{" "}
              <Timestamp value={item.first_seen} mode="date" />
              {/* The representative member's real triage state, always
                  "Open" or "Reopened" -- the resolver's query already
                  excludes every resolved state -- shown explicitly rather
                  than left implicit, which is exactly what let an
                  already-mitigated finding pass for a to-do in the widget
                  this replaced. */}
              <span className={`ml-1 font-medium ${STATE_COLOR[item.state] ?? ""}`}>&middot; {item.state}</span>
              {item.sla_violated && <span className="ml-1 text-destructive">&middot; SLA violated</span>}
            </p>
          </div>
          <SeverityChip severity={item.severity} size="sm" />
        </Link>
      ))}
    </div>
  );
}

const SCORE_COMPONENT_LABEL: Record<string, string> = {
  findings: "Open findings score",
  sla: "SLA compliance score",
  coverage: "Scan coverage score",
  fp_rate: "False-positive rate score",
  trend: "Trend (7d) score",
};

// Render order for the breakdown, and the only place it is declared.
const SCORE_COMPONENT_KEYS = ["findings", "sla", "coverage", "fp_rate", "trend"] as const;

// One grid template, shared by the column header and by every component row,
// so that the label, the meter and the figure each occupy a real track.
// Each row used to be its own `justify-between` flex line, which meant a
// row's meter started wherever that row's label happened to end, and the
// figures never lined up into a column that could be read down.
//
// Label and meter are flexible in a 2:1 ratio, the figure fixed. The figure
// has to be fixed or the numbers stop forming a column, which is the whole
// point; the meter is flexible rather than a fixed 5rem stub so that the
// width a wide card has spare goes into a longer bar -- easier to compare
// five of them down a column -- instead of into a band of nothing between
// the label and the bar.
const SCORE_ROW_GRID = "grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_4.5rem] items-center gap-x-3";

// Same select convention as the Targets and Scans filter bars.
const SCOPE_SELECT_CLASS =
  "h-8 w-full rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

const TREND_DIRECTIONS = ["improving", "stable", "worsening"] as const;
type TrendDirection = (typeof TREND_DIRECTIONS)[number];

type ScoreComponent = SecurityScore["components"][keyof SecurityScore["components"]];

// Validated rather than trusted: a component the backend could not measure
// may carry no direction at all, and `direction` would then be whatever the
// JSON happened to hold.
function trendDirectionOf(c: unknown): TrendDirection | null {
  const direction = (c as { direction?: unknown } | null | undefined)?.direction;
  return TREND_DIRECTIONS.includes(direction as TrendDirection) ? (direction as TrendDirection) : null;
}

/**
 * The 0-100 value of one component, or `null` when it could not be measured.
 *
 * AGENTS.md 1.4: an unmeasured component must never render as a confident
 * zero -- "Trend 0/100" reads as "your posture is as bad as it gets" when
 * what happened is that there is no prior window to compare against yet.
 * `SecurityScoreComponent.score` is typed as a plain `number`, so the shape
 * cannot currently express "unknown"; this reads the field defensively
 * instead of trusting that type, and treats a null/undefined/non-finite
 * score -- or an explicit `measurable: false` -- as unknown. Both spellings
 * are accepted so that whichever one the score API grows, the widget already
 * renders it correctly.
 */
function scoreComponentValue(c: ScoreComponent | undefined): number | null {
  if (!c) return null;
  if ((c as { measurable?: unknown }).measurable === false) return null;
  const raw = (c as { score?: unknown }).score;
  return typeof raw === "number" && Number.isFinite(raw) ? Math.round(raw) : null;
}

// Real underlying metric shown alongside each 0-100 sub-score so it can't be
// misread as a raw count (e.g. "Open findings score: 0" previously looked
// like "0 open findings" when it actually meant "worst possible score",
// the real count (often in the hundreds) lives in c.open_findings on the
// findings component, same field the KPI Cards widget's "Open Findings"
// count is derived from, just default-branch-scoped here vs. all-branches
// there).
function scoreComponentDetail(key: string, c: ScoreComponent): string | null {
  switch (key) {
    case "findings": {
      // The vulnerability count, not the combined total. Licence findings
      // carry no weight in this score, so the total put a number beside the
      // bar that the bar was not computed from -- "13/100 (188 open)" where
      // 148 of the 188 contributed nothing. Named separately so the smaller
      // figure does not read as findings having gone missing.
      const f = c as SecurityScore["components"]["findings"];
      const excluded = f.license_findings_excluded > 0 ? ` · ${f.license_findings_excluded} licence excluded` : "";
      return `${f.open_vulnerabilities} open on default branch${excluded}`;
    }
    case "sla":
      return `${(c as SecurityScore["components"]["sla"]).in_violation} in violation`;
    case "coverage": {
      // (#273) `total_targets` is the *scannable* count: deactivated targets
      // are excluded from both sides of the fraction server-side, because
      // leaving them in the denominator makes the score decay daily for
      // repos nobody is allowed to scan. That exclusion has to be legible
      // HERE, next to the number, not only in the JSON -- an entirely
      // deactivated scope otherwise renders "(0/0 scanned) 100/100", a
      // confident full marks for an estate that scans nothing, which is
      // exactly the confident-zero-for-unmeasured-data anti-pattern.
      const cov = c as SecurityScore["components"]["coverage"];
      const deactivated = cov.deactivated_targets ?? 0;
      if (cov.total_targets === 0 && deactivated > 0) {
        return `no scannable targets · all ${deactivated} deactivated`;
      }
      const excluded = deactivated > 0 ? ` · ${deactivated} deactivated, excluded` : "";
      return `${cov.scanned_targets}/${cov.total_targets} scanned${excluded}`;
    }
    case "fp_rate":
      return `${(c as SecurityScore["components"]["fp_rate"]).false_positives}/${(c as SecurityScore["components"]["fp_rate"]).total_findings} false positives`;
    case "trend": {
      // When the week-over-week comparison could not be made, the server's own
      // wording for why, rendered rather than restated so the explanation
      // lives in one place. Otherwise the direction in words, because the
      // arrow beside the label is decorative and carries no accessible name.
      const t = c as SecurityScore["components"]["trend"];
      return t.measurable ? trendDirectionOf(c) : t.note;
    }
    default:
      return null;
  }
}

type ScoreScope = { kind: "org" } | { kind: "group"; id: number } | { kind: "target"; id: number };

function scoreScopeKey(s: ScoreScope) {
  return s.kind === "org" ? "org" : `${s.kind}:${s.id}`;
}

// No icon is ever drawn for a direction that was never established: a flat
// "stable" dash on a comparison that was not made would claim posture held
// steady over a week this platform has no record of. That is guaranteed
// upstream rather than here -- `trendDirectionOf` returns null for anything
// outside the three real directions, and the caller only asks for an icon
// when the component is measurable -- so this takes the narrow union.
function TrendIcon({ direction }: { direction: TrendDirection }) {
  const Icon = direction === "improving" ? TrendingDown : direction === "worsening" ? TrendingUp : Minus;
  const cls = direction === "improving" ? "text-chart-5" : direction === "worsening" ? "text-destructive" : "text-muted-foreground";
  return <Icon className={`ml-1 inline h-3 w-3 ${cls}`} aria-hidden="true" />;
}

// One row of the breakdown: label and its underlying metric in the first
// track, the meter in the second, the figure in the third. Split out so that
// the measurable and unmeasurable renderings cannot drift apart in the
// number of grid cells they emit, which is what keeps the columns square.
function ScoreComponentRow({
  componentKey,
  component,
  isWeakest,
}: {
  componentKey: string;
  component: ScoreComponent;
  isWeakest: boolean;
}) {
  const label = SCORE_COMPONENT_LABEL[componentKey];
  const value = scoreComponentValue(component);
  const detail = value === null ? null : scoreComponentDetail(componentKey, component);
  const trendDirection = componentKey === "trend" && value !== null ? trendDirectionOf(component) : null;
  const secondary = value === null ? "Not yet measurable" : detail;

  return (
    <div
      data-score-component={componentKey}
      className={`${SCORE_ROW_GRID} rounded-md px-2.5 py-1 transition-colors ${
        isWeakest ? "bg-destructive/10" : "hover:bg-accent/20"
      }`}
    >
      <span className="block min-w-0">
        <span
          className={`block truncate text-xs ${
            value === null
              ? "text-muted-foreground"
              : isWeakest
                ? "font-medium text-destructive"
                : "text-foreground"
          }`}
        >
          {label}
          {trendDirection && <TrendIcon direction={trendDirection} />}
        </span>
        {secondary && <span className="block truncate text-meta">{secondary}</span>}
      </span>

      {value === null ? (
        // Deliberately nothing in the meter track. A zero-length bar is a
        // drawn claim that the value is zero; absence is the honest render.
        <span aria-hidden="true" />
      ) : (
        <ProgressBar value={value} max={100} size="sm" aria-label={`${label}: ${value} out of 100`} />
      )}

      <span
        data-score-figure=""
        className={`text-right font-mono text-xs font-tabular ${
          value === null
            ? "text-muted-foreground"
            : isWeakest
              ? "font-semibold text-destructive"
              : "font-medium text-foreground"
        }`}
      >
        {value === null ? (
          "—"
        ) : (
          <>
            {/* Fixed-width numeral track so the slash, and therefore the
                whole "/100", lands on the same x across every row. */}
            <span className="inline-block w-7 text-right">{value}</span>
            <span className="font-normal text-muted-foreground">/100</span>
          </>
        )}
      </span>
    </div>
  );
}

// Issue #63: composite security health score gauge, with a scope selector
// (org-wide / a Group / a single Target) for drill-down; reuses the same
// scoping concepts as #61's group filtering. The widget's own batched data
// (`initialData`, from GET /api/dashboard/widget-data) covers the org-wide
// default view; switching scope calls GET /api/dashboard/security-score
// directly client-side, since #69's dashboard has no per-widget-instance
// config editor yet for a saved scoped layout. Targets/groups for the
// picker are fetched once on mount (WidgetBody only receives this widget's
// own data, not the whole page's).
//
// Layout: a fixed-width headline column (gauge, grade, and the scope control
// that says what they describe) beside a breakdown column that takes all the
// width left over. The two used to be loose halves of a `justify-between`
// row with a max-width cap on the list, which left a band of unclaimed space
// between them and let the gauge float without any relationship to the rows
// it summarises. The scope picker moved out of the top of the breakdown
// column -- where it read as filtering those rows -- and sits under the
// number it actually rescopes.
function SecurityScoreWidget({ initialData }: { initialData: SecurityScore }) {
  const [scope, setScope] = useState<ScoreScope>({ kind: "org" });
  const scopeSelectId = useId();

  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const { data: groupsData } = useAsyncData<Group[]>(() => api.groups());
  const targets = targetsData ?? [];
  const groups = groupsData ?? [];

  const {
    data: scopedScore,
    error: loadError,
    isInitialLoading: loading,
  } = useAsyncData<SecurityScore>(
    () =>
      scope.kind === "group"
        ? api.securityScore({ groupId: scope.id })
        : api.securityScore({ targetId: (scope as { id: number }).id }),
    { enabled: scope.kind !== "org", deps: [scoreScopeKey(scope)] },
  );

  // Org scope is already batched into `initialData` by
  // GET /api/dashboard/widget-data, so it needs no request of its own.
  // Switching back to it must show that data again rather than whichever
  // repo was last selected; deriving here makes that automatic, where the
  // previous version had to remember to write `initialData` back.
  const score = scope.kind === "org" ? initialData : (scopedScore ?? initialData);
  const error = loadError?.message ?? null;
  const scored = score.target_count > 0;
  const coverage = score.components.coverage as SecurityScore["components"]["coverage"] | undefined;

  return (
    <div className="flex flex-col gap-4">
      {error && <p className="text-sm text-destructive">{error}</p>}

      {/* `flex-wrap`, not a `sm:` breakpoint: this card's width depends on
          the sidebar and the dashboard grid, not on the viewport, so the
          breakdown must drop below the gauge when THIS row runs out of
          room rather than when the window happens to be narrow. The
          breakdown carries no max-width -- it grows to fill whatever is
          left beside the fixed-width gauge, which is what removes the dead
          band that used to sit between the two. */}
      <div className="flex flex-wrap items-start gap-4 sm:gap-6">
        <div className="flex w-60 shrink-0 flex-col items-center gap-3">
          {loading ? (
            <Skeleton className="h-36 w-60" />
          ) : scored && score.score !== null ? (
            <SecurityScoreGauge score={score.score} grade={score.grade} />
          ) : scored ? (
            // Every dimension came back unmeasurable, so there is no composite
            // to draw. A gauge reading 0 with a Grade F would be a verdict on
            // an estate nothing has been measured about yet.
            <div className="flex h-36 w-60 items-center justify-center rounded-lg border border-dashed border-border px-4 text-center text-sm text-muted-foreground">
              Not enough data to score this scope yet.
            </div>
          ) : (
            <div className="flex h-36 w-60 items-center justify-center rounded-lg border border-dashed border-border px-4 text-center text-sm text-muted-foreground">
              No targets in scope.
            </div>
          )}

          <div className="flex w-full flex-col gap-1">
            <label htmlFor={scopeSelectId} className="text-micro text-muted-foreground">
              Scope
            </label>
            <select
              id={scopeSelectId}
              className={SCOPE_SELECT_CLASS}
              value={scoreScopeKey(scope)}
              onChange={(e) => {
                const [kind, id] = e.target.value.split(":");
                if (kind === "org") setScope({ kind: "org" });
                else if (kind === "group") setScope({ kind: "group", id: Number(id) });
                else setScope({ kind: "target", id: Number(id) });
              }}
            >
              <option value="org">All repositories (org-wide)</option>
              {groups.length > 0 && (
                <optgroup label="Groups">
                  {groups.map((g) => (
                    <option key={`group:${g.id}`} value={`group:${g.id}`}>
                      {g.name}
                    </option>
                  ))}
                </optgroup>
              )}
              {targets.length > 0 && (
                <optgroup label="Repositories">
                  {targets.map((t) => (
                    <option key={`target:${t.id}`} value={`target:${t.id}`}>
                      {t.name}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>
        </div>

        <div className="min-w-0 flex-1 basis-[320px]">
          {loading ? (
            <div className="flex flex-col gap-2">
              {SCORE_COMPONENT_KEYS.map((key) => (
                <Skeleton key={key} className="h-8 w-full" />
              ))}
            </div>
          ) : scored ? (
            <div className="flex flex-col gap-0.5">
              <div className={`${SCORE_ROW_GRID} border-b border-border px-2.5 pb-1.5 text-micro text-muted-foreground`}>
                <span>Component</span>
                <span aria-hidden="true" />
                <span className="text-right">Score</span>
              </div>
              {SCORE_COMPONENT_KEYS.map((key) => (
                <ScoreComponentRow
                  key={key}
                  componentKey={key}
                  component={score.components[key]}
                  isWeakest={score.weakest_component === key}
                />
              ))}
            </div>
          ) : null}
        </div>
      </div>

      {/* Full width under both columns: the penalty callout is about the
          score as a whole, and squeezing it into the breakdown column left
          it wrapping awkwardly against the gauge. */}
      {scored && score.weakest_component && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-destructive/30 bg-destructive/15 px-3 py-2 text-xs text-foreground">
          <span className="flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-destructive" />
            <span>
              Score penalty: <strong className="font-semibold text-destructive">{SCORE_COMPONENT_LABEL[score.weakest_component]}</strong>
            </span>
          </span>
          {score.weakest_component === "findings" ? (
            <Link href="/findings?state=Open" className="font-medium text-destructive hover:underline">
              View open findings &rarr;
            </Link>
          ) : score.weakest_component === "sla" ? (
            <Link href="/findings?sla_violated=true&state=Open" className="font-medium text-destructive hover:underline">
              View SLA violations &rarr;
            </Link>
          ) : score.weakest_component === "coverage" ? (
            <Link href="/targets" className="font-medium text-destructive hover:underline">
              Manage targets &rarr;
            </Link>
          ) : null}
        </div>
      )}

      {/* (#273) The server's own wording, rendered rather than restated, so
          the explanation for a suppressed coverage number lives in exactly
          one place. Warning-toned when the whole scope is deactivated: at
          that point the gauge reads a flat 100 for an estate nothing scans,
          and a grey footnote is not enough to carry that. Amber when some
          targets were excluded is deliberate too -- it is a real gap in what
          this score measures, not decoration. */}
      {scored && coverage?.note && (
        <p className={`text-[11px] ${coverage.total_targets === 0 ? "text-warning" : "text-muted-foreground"}`}>
          Coverage: {coverage.note}.
        </p>
      )}
    </div>
  );
}

// Central dispatch: given one layout entry's fetched data, render the right
// widget body. Keeps DashboardBoard free of a giant per-type switch.
export function WidgetBody({ entry }: { entry: WidgetDataEntry | undefined }) {
  if (!entry) return <p className="text-sm text-muted-foreground">Loading...</p>;
  if (entry.error) return <ErrorState message={entry.error} />;
  if (!entry.data) return <EmptyState>No data.</EmptyState>;

  switch (entry.widget_id) {
    case "kpi_cards":
      return <KpiCardsWidget data={entry.data as KpiCardsData} />;
    case "sla_compliance":
      return <SlaComplianceWidget data={entry.data as SlaComplianceData} />;
    case "findings_trend":
      return <FindingsTrendWidget data={entry.data as FindingsTrendData} />;
    case "top_risky_repos":
      return <TopRiskyReposWidget data={entry.data as TopRiskyReposData} />;
    case "cve_timeline":
      return <CveTimelineWidget data={entry.data as CveTimelineData} />;
    case "recent_findings":
      return <NeedsActionQueueWidget data={entry.data as NeedsActionQueueData} />;
    case "security_score":
      return <SecurityScoreWidget initialData={entry.data as SecurityScore} />;
    case "fp_auto_suppressions":
      return <FpAutoSuppressionsWidget data={entry.data as FpAutoSuppressionsData} />;
    case "live_scan_activity":
      return <LiveScanActivityWidget data={entry.data as LiveScanActivityData} />;
    case "ai_ml_risk":
      return <AiMlRiskWidget data={entry.data as AiMlRiskData} />;
    case "guardrail_activity":
      return <GuardrailActivityWidget data={entry.data as GuardrailActivityData} />;
    default:
      return <ErrorState message={`unknown widget type: ${entry.widget_id}`} />;
  }
}
