"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
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
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { SEVERITY_COLOR } from "@/lib/severity";
import { FindingsTrendLine } from "@/components/charts/findings-trend-line";
import { SecurityScoreGauge } from "@/components/charts/security-score-gauge";
import { api } from "@/lib/api";
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
    { icon: ShieldAlert, iconClass: "bg-destructive/10 text-destructive", value: data.open, label: "Open Vulnerabilities" },
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
            <p className="truncate text-sm text-foreground">{f.title}</p>
            <p className="text-xs text-muted-foreground">
              {f.target_name ?? `target #${f.target_id}`} &middot; {f.tool} &middot; {formatDate(f.first_seen)}
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
  findings: "Open findings",
  sla: "SLA compliance",
  coverage: "Scan coverage",
  fp_rate: "False-positive rate",
  trend: "Trend (7d)",
};

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
  const [score, setScore] = useState<SecurityScore>(initialData);
  const [targets, setTargets] = useState<Target[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.targets().then(setTargets).catch(() => {});
    api.groups().then(setGroups).catch(() => {});
  }, []);

  useEffect(() => {
    if (scope.kind === "org") {
      setScore(initialData);
      return;
    }
    setLoading(true);
    setError(null);
    const req = scope.kind === "group" ? api.securityScore({ groupId: scope.id }) : api.securityScore({ targetId: scope.id });
    req
      .then(setScore)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load security score"))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scoreScopeKey(scope)]);

  return (
    <div className="flex flex-col gap-3">
      <select
        className="self-end rounded-md border border-input bg-secondary px-2 py-1 text-xs text-foreground"
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
        <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start sm:justify-around">
          <SecurityScoreGauge score={score.score} grade={score.grade} />
          <div className="grid w-full max-w-sm grid-cols-1 gap-1.5 text-xs">
            {(Object.keys(SCORE_COMPONENT_LABEL) as (keyof typeof SCORE_COMPONENT_LABEL)[]).map((key) => {
              const c = score.components[key as keyof SecurityScore["components"]];
              const isWeakest = score.weakest_component === key;
              return (
                <div key={key} className={`flex items-center justify-between rounded-md px-2 py-1 ${isWeakest ? "bg-destructive/10" : ""}`}>
                  <span className={isWeakest ? "font-medium text-destructive" : "text-muted-foreground"}>
                    {SCORE_COMPONENT_LABEL[key]}
                    {key === "trend" && <TrendIcon direction={score.components.trend.direction} />}
                  </span>
                  <span className={isWeakest ? "font-semibold text-destructive" : "font-medium text-foreground"}>{Math.round(c.score)}</span>
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
    default:
      return <ErrorState message={`unknown widget type: ${entry.widget_id}`} />;
  }
}
