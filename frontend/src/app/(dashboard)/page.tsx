import Link from "next/link";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_COLOR } from "@/lib/severity";
import { ShieldAlert, ShieldCheck, GitBranch, Activity, CheckCircle2 } from "lucide-react";
import { SeverityPie } from "@/components/charts/severity-pie";
import { ToolBar } from "@/components/charts/tool-bar";

export default async function PosturePage() {
  const [summary, posture, stats] = await Promise.all([
    api.summary().catch(() => ({ total: 0, open: 0, mitigated: 0 })),
    api.posture().catch(() => []),
    api.stats().catch(() => ({ open: 0, by_severity: {} as Record<string, number>, by_tool: {} as Record<string, number> })),
  ]);

  const critical = stats.by_severity["Critical"] ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Security Overview</h1>
        <p className="text-sm text-muted-foreground">Real-time security posture, default branches only</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <KpiCard icon={ShieldAlert} iconClass="bg-destructive/10 text-destructive" value={summary.open} label="Open Vulnerabilities" />
        <KpiCard icon={ShieldAlert} iconClass="bg-chart-3/10 text-chart-3" value={critical} label="Critical Issues" />
        <KpiCard icon={GitBranch} iconClass="bg-primary/10 text-primary" value={posture.length} label="Targets Onboarded" />
        <KpiCard icon={CheckCircle2} iconClass="bg-chart-5/10 text-chart-5" value={summary.mitigated} label="Mitigated" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="border-border bg-card lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Activity className="h-4 w-4 text-primary" />
              Open Findings by Tool
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ToolBar data={stats.by_tool} />
          </CardContent>
        </Card>

        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-foreground">
              <ShieldCheck className="h-4 w-4 text-primary" />
              Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityPie data={stats.by_severity} />
          </CardContent>
        </Card>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">Targets</h2>
        {posture.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No targets yet. Add one on the{" "}
            <Link href="/targets" className="text-primary underline">
              Targets
            </Link>{" "}
            page.
          </p>
        )}
        <div className="flex flex-col gap-3">
          {posture.map(({ target, breakdown }) => (
            <Link key={target.id} href={`/targets/${target.id}`}>
              <Card className="border-border bg-card transition-colors hover:border-primary/40">
                <CardContent className="flex items-center justify-between px-4 py-3">
                  <div>
                    <span className="font-medium text-foreground">{target.name}</span>
                    <span className="ml-2 text-xs text-muted-foreground">
                      {target.label} · weight {target.criticality_weight}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    {Object.entries(breakdown).map(([severity, states]) => {
                      const openCount = states["Open"] || 0;
                      if (openCount === 0) return null;
                      return (
                        <Badge key={severity} variant="outline" className={SEVERITY_COLOR[severity]}>
                          {severity}: {openCount}
                        </Badge>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

function KpiCard({
  icon: Icon,
  iconClass,
  value,
  label,
}: {
  icon: React.ElementType;
  iconClass: string;
  value: number;
  label: string;
}) {
  return (
    <Card className="border-border bg-card">
      <CardContent className="flex items-center gap-4 px-4 py-4">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${iconClass}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-foreground">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}
