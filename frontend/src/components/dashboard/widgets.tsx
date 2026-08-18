"use client";

import Link from "next/link";
import { useState } from "react";
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
import { SEVERITY_COLOR } from "@/lib/severity";
import { LOG_STATUS_COLOR } from "@/components/pr-guardrail-log";
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
  RecentFindingsData,
  SecurityScore,
  FpAutoSuppressionsData,
  LiveScanActivityData,
  AiMlRiskData,
  GuardrailActivityData,
  Group,
  Target,
} from "@/lib/api";

// Issue #69: the concrete render for each widget type in the catalog --
// deliberately one component per real widget, not a generic chart
// interpreter. `icon`/`label` here drive both the "Add Widget" picker and
// the WidgetShell header; `render` consumes exactly the shape returned by
// that widget's app.core.widgets resolver on the backend.
export const WIDGET_META: Record<WidgetId, { label: string; icon: React.ElementType; colSpanClass?: string }> = {
  security_score: { label: "Security Score", icon: Gauge, colSpanClass: "lg:col-span-3" },
  kpi_cards: { label: "KPI Cards", icon: ShieldAlert, colSpanClass: "lg:col-span-3" },
  sla_compliance: { label: "SLA Compliance", icon: Timer, colSpanClass: "lg:col-span-3" },
  findings_trend: { label: "Findings Over Time", icon: Activity, colSpanClass: "lg:col-span-2" },
  top_risky_repos: { label: "Top Risky Repos", icon: GitBranch },
  cve_timeline: { label: "CVE Timeline", icon: Bug, colSpanClass: "lg:col-span-2" },
  recent_findings: { label: "Recent Findings", icon: ListChecks },
  fp_auto_suppressions: { label: "Auto-Suppressed Findings", icon: ShieldCheck },
  live_scan_activity: { label: "Live Scan Activity", icon: Loader2 },
  ai_ml_risk: { label: "AI/ML Risk", icon: Bot },
  guardrail_activity: { label: "Guardrail Activity", icon: GitPullRequest, colSpanClass: "lg:col-span-2" },
};

// Locale-independent date formatting (YYYY-MM-DD from the ISO timestamp
// directly, no Date/toLocaleDateString) -- the server and the browser
// render this same server component's HTML with potentially different
// locales/timezone configs, and toLocaleDateString() previously produced
// a real hydration mismatch (e.g. "13/08/2026" server-side vs
// "8/13/2026" client-side) that broke the initial page load.
function formatDate(iso: string): string {
  return iso.slice(0, 10);
}

// Widget-scoped, compact variants of the shared empty/error patterns
// (src/components/ui/empty-state.tsx, error-state.tsx) -- widgets need
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
    // Label unified to "Findings" (#116) -- was "Open Vulnerabilities" while
    // the sidebar nav said "Vulnerabilities" and the page header said
    // "Findings"; all three now use the same term.
    { icon: ShieldAlert, iconClass: "bg-destructive/10 text-destructive", value: data.open, label: "Open Findings" },
    { icon: AlertTriangle, iconClass: "bg-chart-3/10 text-chart-3", value: data.critical, label: "Critical Issues" },
    { icon: GitBranch, iconClass: "bg-primary/10 text-accent-strong", value: data.targets, label: "Targets Onboarded" },
    { icon: CheckCircle2, iconClass: "bg-chart-5/10 text-chart-5", value: data.mitigated, label: "Mitigated" },
  ];
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {items.map((it) => (
        <div key={it.label} className="flex items-center gap-3">
          <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${it.iconClass}`}>
            <it.icon className="h-5 w-5" />
          </div>
          <div>
            <p className="text-2xl font-bold text-foreground">{it.value}</p>
            <p className="text-xs text-muted-foreground">{it.label}</p>
          </div>
        </div>
      ))}
    </div>
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
  return (
    <div className="flex items-center gap-6">
      <div>
        <p className="text-2xl font-bold text-foreground">{data.with_sla}</p>
        <p className="text-xs text-muted-foreground">Open findings with an SLA</p>
      </div>
      <div>
        <p className={`text-2xl font-bold ${data.in_violation > 0 ? "text-destructive" : "text-foreground"}`}>{data.in_violation}</p>
        <p className="text-xs text-muted-foreground">In violation</p>
      </div>
      <div>
        <p className="text-2xl font-bold text-chart-5">{data.compliant}</p>
        <p className="text-xs text-muted-foreground">Within SLA</p>
      </div>
    </div>
  );
}

function FpAutoSuppressionsWidget({ data }: { data: FpAutoSuppressionsData }) {
  if (data.count === 0) {
    return (
      <EmptyState>
        No findings auto-suppressed since {formatDate(data.since)}. Rules are learned when a finding is triaged{" "}
        &quot;False Positive&quot; -- manage them on the{" "}
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
        <p className="text-xs text-muted-foreground">Auto-suppressed since {formatDate(data.since)}</p>
      </div>
    </div>
  );
}

function FindingsTrendWidget({ data }: { data: FindingsTrendData }) {
  return <FindingsTrendLine data={data} />;
}

// Issue #224: surfaces GET /api/scans/active's data (previously only
// visible on the Scans page and each target's own detail page) directly on
// the dashboard -- "is anything running right now" is a question people
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
// dashboard-level presence -- an org running them had to already know to
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
  return (
    <div className="flex flex-col gap-2">
      {data.items.map((r) => (
        <Link key={r.target_id} href={`/targets/${r.target_id}`} className="flex items-center justify-between rounded-md px-2 py-1.5 hover:bg-accent/40">
          <span className="text-sm text-foreground">{r.target_name}</span>
          <div className="flex gap-2">
            {r.critical > 0 && <Badge variant="outline" className={SEVERITY_COLOR["Critical"]}>Critical: {r.critical}</Badge>}
            {r.high > 0 && <Badge variant="outline" className={SEVERITY_COLOR["High"]}>High: {r.high}</Badge>}
            {r.critical === 0 && r.high === 0 && <span className="text-xs text-muted-foreground">No critical/high open</span>}
          </div>
        </Link>
      ))}
    </div>
  );
}

function CveTimelineWidget({ data }: { data: CveTimelineData }) {
  if (data.items.length === 0) return <EmptyState>No CVE findings yet.</EmptyState>;
  return (
    <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
      {data.items.map((item) => (
        <div key={item.finding_id} className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-accent-strong">{item.cve_id}</span>
              {item.kev_listed && <Badge variant="outline" className="border-destructive/40 bg-destructive/20 text-destructive">KEV</Badge>}
            </div>
            <p className="truncate text-sm text-foreground">{item.title}</p>
            <p className="text-xs text-muted-foreground">{item.target_name ?? `target #${item.target_id}`} &middot; {formatDate(item.first_seen)}</p>
          </div>
          <Badge variant="outline" className={SEVERITY_COLOR[item.severity]}>{item.severity}</Badge>
        </div>
      ))}
    </div>
  );
}

function RecentFindingsWidget({ data }: { data: RecentFindingsData }) {
  if (data.items.length === 0) return <EmptyState>No findings yet.</EmptyState>;
  return (
    <div className="flex flex-col gap-2 max-h-80 overflow-y-auto">
      {data.items.map((f) => (
        <div key={f.finding_id} className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2">
          <div className="min-w-0">
            {/* Issue #117/#119: reuse the shared truncate-with-tooltip
                affordance so a long title isn't silently clipped, and show
                file_path in the subtitle -- the same rule can legitimately
                fire on several files in one scan (e.g. Semgrep's
                django-no-csrf-token across multiple templates), which
                otherwise renders as visually-identical rows since title/
                target/tool/date alone don't distinguish them. */}
            <TruncateTooltip
              text={f.title}
              subtext={f.file_path}
              className="text-sm text-foreground"
            />
            <p className="truncate text-xs text-muted-foreground">
              {f.target_name ?? `target #${f.target_id}`} &middot; {f.tool} &middot; {f.file_path} &middot; {formatDate(f.first_seen)}
              {f.sla_violated && <span className="ml-1 text-destructive">&middot; SLA violated</span>}
            </p>
          </div>
          <Badge variant="outline" className={SEVERITY_COLOR[f.severity]}>{f.severity}</Badge>
        </div>
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

// Real underlying metric shown alongside each 0-100 sub-score so it can't be
// misread as a raw count (e.g. "Open findings score: 0" previously looked
// like "0 open findings" when it actually meant "worst possible score" --
// the real count (often in the hundreds) lives in c.open_findings on the
// findings component, same field the KPI Cards widget's "Open Findings"
// count is derived from, just default-branch-scoped here vs. all-branches
// there).
function scoreComponentDetail(key: string, c: SecurityScore["components"][keyof SecurityScore["components"]]): string | null {
  switch (key) {
    case "findings":
      return `${(c as SecurityScore["components"]["findings"]).open_findings} open on default branch`;
    case "sla":
      return `${(c as SecurityScore["components"]["sla"]).in_violation} in violation`;
    case "coverage":
      return `${(c as SecurityScore["components"]["coverage"]).scanned_targets}/${(c as SecurityScore["components"]["coverage"]).total_targets} scanned`;
    case "fp_rate":
      return `${(c as SecurityScore["components"]["fp_rate"]).false_positives}/${(c as SecurityScore["components"]["fp_rate"]).total_findings} false positives`;
    default:
      return null;
  }
}

type ScoreScope = { kind: "org" } | { kind: "group"; id: number } | { kind: "target"; id: number };

function scoreScopeKey(s: ScoreScope) {
  return s.kind === "org" ? "org" : `${s.kind}:${s.id}`;
}

function TrendIcon({ direction }: { direction: "improving" | "stable" | "worsening" }) {
  const Icon = direction === "improving" ? TrendingDown : direction === "worsening" ? TrendingUp : Minus;
  const cls = direction === "improving" ? "text-chart-5" : direction === "worsening" ? "text-destructive" : "text-muted-foreground";
  return <Icon className={`ml-1 inline h-3 w-3 ${cls}`} />;
}

// Issue #63: composite security health score gauge, with a scope selector
// (org-wide / a Group / a single Target) for drill-down -- reuses the same
// scoping concepts as #61's group filtering. The widget's own batched data
// (`initialData`, from GET /api/dashboard/widget-data) covers the org-wide
// default view; switching scope calls GET /api/dashboard/security-score
// directly client-side, since #69's dashboard has no per-widget-instance
// config editor yet for a saved scoped layout. Targets/groups for the
// picker are fetched once on mount (WidgetBody only receives this widget's
// own data, not the whole page's).
function SecurityScoreWidget({ initialData }: { initialData: SecurityScore }) {
  const [scope, setScope] = useState<ScoreScope>({ kind: "org" });

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
  // repo was last selected -- deriving here makes that automatic, where the
  // previous version had to remember to write `initialData` back.
  const score = scope.kind === "org" ? initialData : (scopedScore ?? initialData);
  const error = loadError?.message ?? null;

  return (
    <div className="flex flex-col gap-3">
      <select
        className="self-end rounded-md border border-input bg-secondary px-2 py-1 text-xs text-foreground"
        aria-label="Security score scope"
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

      {error && <p className="text-sm text-destructive">{error}</p>}
      {loading ? (
        <div className="flex items-center justify-center py-6">
          <Skeleton className="h-32 w-56" />
        </div>
      ) : score.target_count === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">No targets in scope.</p>
      ) : (
        <div className="mx-auto flex w-full max-w-4xl flex-wrap items-center justify-center gap-6 sm:gap-8">
          {/* max-w-4xl (896px), not max-w-2xl (672px): the gauge (280px) +
              gap (32px) + score list (up to 480px) need ~792px to sit on one
              line, and 672px was just short of that -- forcing an unwanted
              wrap on every desktop viewport instead of only the ones that
              actually need it.

              Issue #173/#224: this row used to be `justify-around`, then a
              `justify-center` pair with a `w-full max-w-md` list -- but
              `width: 100%` on a flex child ignores the parent's centering and
              just claims the available row width for itself, so on a wide
              dashboard card the gauge stayed pinned to the left, the list
              claimed a large but not-full-width slab on the right, and the
              gap between them read as a layout bug rather than intentional
              spacing. It was then switched to a fixed-width list gated by a
              `sm:` breakpoint, which broke differently: `sm:flex-row` doesn't
              know how wide THIS card actually is (that depends on the
              sidebar + the dashboard grid, not the viewport), so on any
              layout narrower than the gauge+list's combined ~790px but still
              past the 640px `sm:` breakpoint, the row forced both fixed-width
              children into a space too small for them -- flexbox's default
              shrink then compressed the gauge's box (see shrink-0 on
              SecurityScoreGauge's own root for why that broke the arc/number
              alignment) instead of just wrapping. `flex-wrap` here reacts to
              the row's REAL available width instead of a viewport guess: the
              list drops to its own line below the gauge exactly when there
              isn't room beside it.

              The list itself must stay shrinkable (`w-full max-w-[480px]`,
              no `shrink-0`) even though that looks backwards -- this whole
              dashboard's widget grid (dashboard-board.tsx) has no explicit
              `grid-cols-1` below `lg:`, so its single implicit column sizes
              itself to content rather than clamping to the viewport. Giving
              the list a `shrink-0` + fixed pixel width once (480px) made its
              *used* width a hard 480px regardless of how little room was
              actually available, which the grid dutifully accommodated by
              growing the entire page 1000+px wider than the viewport on
              mobile instead of wrapping. Letting it shrink is what lets the
              grid track -- and the whole page -- stay pinned to the real
              viewport width; flex-wrap plus a max-width cap is enough to
              keep it from looking cramped once there IS room. */}
          <SecurityScoreGauge score={score.score} grade={score.grade} />
          <div className="grid w-full max-w-[480px] grid-cols-1 gap-1.5 text-xs">
            {(Object.keys(SCORE_COMPONENT_LABEL) as (keyof typeof SCORE_COMPONENT_LABEL)[]).map((key) => {
              const c = score.components[key as keyof SecurityScore["components"]];
              const isWeakest = score.weakest_component === key;
              const detail = scoreComponentDetail(key, c);
              return (
                <div key={key} className={`flex items-center justify-between rounded-md px-2 py-1 ${isWeakest ? "bg-destructive/10" : ""}`}>
                  <span className={isWeakest ? "font-medium text-destructive" : "text-muted-foreground"}>
                    {SCORE_COMPONENT_LABEL[key]}
                    {key === "trend" && <TrendIcon direction={score.components.trend.direction} />}
                    {detail && <span className="ml-1.5 text-[10px] text-muted-foreground/70">({detail})</span>}
                  </span>
                  <span className={isWeakest ? "font-semibold text-destructive" : "font-medium text-foreground"}>{Math.round(c.score)}/100</span>
                </div>
              );
            })}
            {score.weakest_component && (
              <p className="mt-1 text-[11px] text-muted-foreground">
                Dragged down by <span className="font-medium text-foreground">{SCORE_COMPONENT_LABEL[score.weakest_component]}</span>.
              </p>
            )}
          </div>
        </div>
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
      return <RecentFindingsWidget data={entry.data as RecentFindingsData} />;
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
