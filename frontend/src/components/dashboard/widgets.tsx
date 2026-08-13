"use client";

import Link from "next/link";
import {
  ShieldAlert,
  GitBranch,
  CheckCircle2,
  Timer,
  Activity,
  Bug,
  AlertTriangle,
  ListChecks,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_COLOR } from "@/lib/severity";
import { FindingsTrendLine } from "@/components/charts/findings-trend-line";
import type {
  WidgetId,
  WidgetDataEntry,
  KpiCardsData,
  FindingsTrendData,
  CveTimelineData,
  SlaComplianceData,
  TopRiskyReposData,
  RecentFindingsData,
} from "@/lib/api";

// Issue #69: the concrete render for each widget type in the catalog --
// deliberately one component per real widget, not a generic chart
// interpreter. `icon`/`label` here drive both the "Add Widget" picker and
// the WidgetShell header; `render` consumes exactly the shape returned by
// that widget's app.core.widgets resolver on the backend.
export const WIDGET_META: Record<WidgetId, { label: string; icon: React.ElementType; colSpanClass?: string }> = {
  kpi_cards: { label: "KPI Cards", icon: ShieldAlert, colSpanClass: "lg:col-span-3" },
  sla_compliance: { label: "SLA Compliance", icon: Timer, colSpanClass: "lg:col-span-3" },
  findings_trend: { label: "Findings Over Time", icon: Activity, colSpanClass: "lg:col-span-2" },
  top_risky_repos: { label: "Top Risky Repos", icon: GitBranch },
  cve_timeline: { label: "CVE Timeline", icon: Bug, colSpanClass: "lg:col-span-2" },
  recent_findings: { label: "Recent Findings", icon: ListChecks },
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

function ErrorState({ message }: { message: string }) {
  return <p className="text-sm text-destructive">Couldn&apos;t load widget: {message}</p>;
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

function KpiCardsWidget({ data }: { data: KpiCardsData }) {
  const items = [
    { icon: ShieldAlert, iconClass: "bg-destructive/10 text-destructive", value: data.open, label: "Open Vulnerabilities" },
    { icon: AlertTriangle, iconClass: "bg-chart-3/10 text-chart-3", value: data.critical, label: "Critical Issues" },
    { icon: GitBranch, iconClass: "bg-primary/10 text-primary", value: data.targets, label: "Targets Onboarded" },
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
        <Link href="/admin" className="text-primary underline">
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
              <span className="font-mono text-xs text-primary">{item.cve_id}</span>
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
    default:
      return <ErrorState message={`unknown widget type: ${entry.widget_id}`} />;
  }
}
