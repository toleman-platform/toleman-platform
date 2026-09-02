"use client";

import { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  GitBranch,
  CheckCircle2,
  Terminal,
  Activity,
  ExternalLink,
  Palette,
  LayoutGrid,
  Type,
  Ruler,
  Layers,
} from "lucide-react";
import { PageHeader } from "@/components/ui/page-header";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { ProgressBar } from "@/components/ui/progress-bar";
import { SeverityChip } from "@/components/ui/severity-chip";
import { AlertBanner } from "@/components/ui/alert-banner";
import { StatusBadge } from "@/components/ui/status-badge";
import { FilterBar, FilterPillItem } from "@/components/ui/filter-bar";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Icon } from "@/components/ui/icon";
import { TYPE_SCALE, SPATIAL_SCALE, RADIUS_SCALE } from "@/tokens";

export default function DesignSystemGalleryPage() {
  const [demoSearch, setDemoSearch] = useState("CVE-2024");
  const [demoPills, setDemoPills] = useState<Array<{ id: string; label: string; value: string }>>([
    { id: "sev", label: "Severity", value: "Critical" },
    { id: "target", label: "Target", value: "customer-portal-web" },
    { id: "sla", label: "SLA", value: "Violated" },
  ]);

  const activePills: FilterPillItem[] = demoPills.map((pill) => ({
    ...pill,
    onRemove: () => setDemoPills((prev) => prev.filter((x) => x.id !== pill.id)),
  }));

  return (
    <div className="mx-auto max-w-6xl space-y-8 p-6">
      <PageHeader
        title="Toleman Design System"
        description="Core design tokens, typography rules, accessibility benchmarks, and reusable UI primitives."
        badge={
          <Badge variant="outline" className="border-primary/40 bg-primary/10 text-primary">
            v1.0 Design Tokens
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => window.open("/", "_blank")}>
              <ExternalLink className="h-3.5 w-3.5" />
              Live Dashboard
            </Button>
          </div>
        }
      />

      {/* Section 1: Color Tokens & Surfaces */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Palette className="h-4 w-4 text-primary" />
            1. Color Tokens & Surface Hierarchy
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <p className="text-xs text-muted-foreground">
            Standardized neutral-charcoal canvas with dedicated semantic severity tokens. Fully WCAG AA compliant.
          </p>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-primary mb-2" />
              <div className="font-mono text-xs font-semibold">Primary / Cyan</div>
              <div className="text-[11px] text-muted-foreground">#22c1d9</div>
            </div>
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-destructive mb-2" />
              <div className="font-mono text-xs font-semibold">Critical / Red</div>
              <div className="text-[11px] text-muted-foreground">#f0555c</div>
            </div>
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-chart-3 mb-2" />
              <div className="font-mono text-xs font-semibold">High / Amber</div>
              <div className="text-[11px] text-muted-foreground">#f2924a</div>
            </div>
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-chart-5 mb-2" />
              <div className="font-mono text-xs font-semibold">Success / Green</div>
              <div className="text-[11px] text-muted-foreground">#34b774</div>
            </div>
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-card border mb-2" />
              <div className="font-mono text-xs font-semibold">Card Surface</div>
              <div className="text-[11px] text-muted-foreground">--card</div>
            </div>
            <div className="rounded-md border p-3 bg-background">
              <div className="h-6 w-full rounded bg-secondary border mb-2" />
              <div className="font-mono text-xs font-semibold">Secondary Sunken</div>
              <div className="text-[11px] text-muted-foreground">--secondary</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Section 2: Typography & Scalable Type Scale System */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Type className="h-4 w-4 text-primary" />
            2. Scalable Typography & Type Scale
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 pt-4">
          <p className="text-xs text-muted-foreground">
            Fluid, modular typographic hierarchy designed for enterprise DevSecOps workflows. Combines Plus Jakarta Sans (display/body) with Geist Mono (tabular numerals/code tokens).
          </p>

          <div className="divide-y divide-border rounded-lg border bg-background overflow-hidden">
            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-display</span>
                <p className="text-meta">{TYPE_SCALE.display.size} · {TYPE_SCALE.display.weight} Wt · {TYPE_SCALE.display.tracking}</p>
              </div>
              <div className="text-display sm:w-3/4">Enterprise Vulnerability Terrain</div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-title</span>
                <p className="text-meta">{TYPE_SCALE.title.size} · {TYPE_SCALE.title.weight} Wt · {TYPE_SCALE.title.tracking}</p>
              </div>
              <div className="text-title sm:w-3/4">Posture & Guardrail Management</div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-heading</span>
                <p className="text-meta">{TYPE_SCALE.heading.size} · {TYPE_SCALE.heading.weight} Wt · {TYPE_SCALE.heading.tracking}</p>
              </div>
              <div className="text-heading sm:w-3/4">Critical SLA Compliance Policies</div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-subheading</span>
                <p className="text-meta">{TYPE_SCALE.subheading.size} · {TYPE_SCALE.subheading.weight} Wt · {TYPE_SCALE.subheading.tracking}</p>
              </div>
              <div className="text-subheading sm:w-3/4">Active PR Diff-Scan Targets</div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-body</span>
                <p className="text-meta">{TYPE_SCALE.body.size} · {TYPE_SCALE.body.weight} Wt · {TYPE_SCALE.body.leading} leading</p>
              </div>
              <div className="text-body sm:w-3/4 text-muted-foreground">
                Toleman evaluates dependency trees, infrastructure manifests, and AI/ML model artifacts with sub-second real-time scoring.
              </div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-body-sm</span>
                <p className="text-meta">{TYPE_SCALE.bodySm.size} · {TYPE_SCALE.bodySm.weight} Wt · {TYPE_SCALE.bodySm.leading} leading</p>
              </div>
              <div className="text-body-sm sm:w-3/4 text-muted-foreground">
                Secondary descriptive metadata and contextual guidance across dashboard cards and audit entries.
              </div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-caption</span>
                <p className="text-meta">{TYPE_SCALE.caption.size} · {TYPE_SCALE.caption.weight} Wt · {TYPE_SCALE.caption.leading} leading</p>
              </div>
              <div className="text-caption sm:w-3/4 text-muted-foreground">
                semgrep · src/auth/token_verifier.py:142 · rule-jwt-signature-bypass
              </div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-meta / .text-micro</span>
                <p className="text-meta">{TYPE_SCALE.meta.size} / {TYPE_SCALE.micro.size} · {TYPE_SCALE.meta.weight}/{TYPE_SCALE.micro.weight} Wt</p>
              </div>
              <div className="flex items-center gap-3 sm:w-3/4">
                <span className="text-meta">LAST SCANNED 2H AGO</span>
                <span className="text-micro rounded border border-border px-1.5 py-0.5 font-mono">CVSS 9.8</span>
                <span className="text-code font-semibold text-foreground">CVE-2024-3094</span>
              </div>
            </div>

            <div className="flex flex-col gap-2 p-4 sm:flex-row sm:items-baseline sm:justify-between">
              <div className="sm:w-1/4">
                <span className="font-mono text-xs font-semibold text-primary">.text-metric-*</span>
                <p className="text-meta">Tabular Metric Figures (xl/lg/md)</p>
              </div>
              <div className="flex items-baseline gap-6 sm:w-3/4">
                <div>
                  <div className="text-metric-xl text-destructive">1,410</div>
                  <div className="text-meta">METRIC-XL (30PX)</div>
                </div>
                <div>
                  <div className="text-metric-lg text-chart-3">89.4%</div>
                  <div className="text-meta">METRIC-LG (24PX)</div>
                </div>
                <div>
                  <div className="text-metric-md text-chart-5">+24/D</div>
                  <div className="text-meta">METRIC-MD (18PX)</div>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Section 3: Spacing, Grid & Proportions (The Rules of Thumb) */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Ruler className="h-4 w-4 text-primary" />
            3. Spacing, Grid & Proportions (The Rules of Thumb)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 pt-4">
          <p className="text-xs text-muted-foreground">
            Strict 4px/8px base spatial grid with concentric corner radii ($R_&#123;outer&#125; = R_&#123;inner&#125; + \text&#123;padding&#125;$) and proximity-based visual grouping rules.
          </p>

          {/* Sub-section 1: Spatial Step Ruler */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              A. 4px / 8px Spatial Step Ruler
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {(["2xs", "xs", "sm", "md", "xl"] as const).map((step) => {
                const item = SPATIAL_SCALE[step];
                return (
                  <div key={step} className="rounded-lg border bg-background p-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-semibold text-primary">{item.name}</span>
                      <span className="text-meta">{item.px}px ({item.rem})</span>
                    </div>
                    <div
                      className="mt-2 h-2 rounded bg-primary/30"
                      style={{ width: `${Math.min(item.px, 48)}px` }}
                    />
                    <p className="mt-1 text-[11px] text-muted-foreground">{item.usage}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Sub-section 2: Proximity & Concentric Radii Rule */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Concentric Radii Rule Card */}
            <div className="rounded-xl border bg-background p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                <h4 className="text-xs font-semibold text-foreground">Concentric Radius Rule ($R_&#123;outer&#125; = R_&#123;inner&#125; + P$)</h4>
              </div>
              <p className="text-xs text-muted-foreground">
                Prevents corner distortion. When an inner tile sits inside a container with 12px padding, the outer radius scales proportionally with the inner radius.
              </p>
              <div className="rounded-xl border border-primary/40 bg-card p-3 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary">
                  <ShieldAlert className="h-5 w-5" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-foreground">
                    Outer: {RADIUS_SCALE.xl.name} ({RADIUS_SCALE.xl.px}px) · Inner: {RADIUS_SCALE.md.name} ({RADIUS_SCALE.md.px}px)
                  </div>
                  <div className="text-meta text-muted-foreground">Padding = 12px · Symmetrical corner flow</div>
                </div>
              </div>
            </div>

            {/* Law of Proximity Rule Card */}
            <div className="rounded-xl border bg-background p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                <h4 className="text-xs font-semibold text-foreground">The Law of Proximity (Hierarchy)</h4>
              </div>
              <p className="text-xs text-muted-foreground">
                Internal child spacing ($gap \le 4px$) must be visibly tighter than component margin gaps ($gap \ge 16px$).
              </p>
              <div className="space-y-2 rounded-lg border bg-card p-3">
                <div className="flex items-center justify-between border-b pb-2">
                  <div className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-destructive" />
                    <span className="text-xs font-semibold text-foreground">CVE-2024-41110</span>
                  </div>
                  <span className="text-meta">gap-1.5 (6px)</span>
                </div>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-xs text-muted-foreground">Section separation offset</span>
                  <span className="text-meta">gap-4 (16px)</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Section 4: Standardized Icon Wrapper System */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icon icon={ShieldAlert} size="md" tone="primary" />
            4. Standardized Icon Wrapper System
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6 pt-4">
          <p className="text-xs text-muted-foreground">
            Strict icon scale hierarchy ensuring geometric consistency across chips, inputs, nav items, and stat headers.
          </p>

          {/* Size Variants */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              A. Sizing Variants Scale
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              {[
                { size: "xs" as const, label: "xs (12px)", usage: "Micro chips & chevrons" },
                { size: "sm" as const, label: "sm (14px)", usage: "Search & metadata rows" },
                { size: "md" as const, label: "md (16px)", usage: "Default controls & buttons" },
                { size: "lg" as const, label: "lg (20px)", usage: "Card headers & stats" },
                { size: "xl" as const, label: "xl (24px)", usage: "Feature callouts & alerts" },
                { size: "2xl" as const, label: "2xl (32px)", usage: "Empty states & hero banners" },
              ].map(({ size, label, usage }) => (
                <div key={size} className="flex flex-col items-center justify-center rounded-lg border bg-background p-3 text-center">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-secondary text-primary">
                    <Icon icon={ShieldAlert} size={size} />
                  </div>
                  <span className="mt-2 font-mono text-xs font-semibold text-foreground">{label}</span>
                  <span className="mt-0.5 text-[10px] text-muted-foreground">{usage}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Semantic Color Tones */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              B. Semantic Color Tones
            </h3>
            <div className="flex flex-wrap items-center gap-4 rounded-lg border bg-background p-4">
              {[
                { tone: "default" as const, label: "Default" },
                { tone: "primary" as const, label: "Primary" },
                { tone: "destructive" as const, label: "Destructive" },
                { tone: "warning" as const, label: "Warning" },
                { tone: "success" as const, label: "Success" },
                { tone: "muted" as const, label: "Muted" },
              ].map(({ tone, label }) => (
                <div key={tone} className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-xs">
                  <Icon icon={ShieldAlert} size="sm" tone={tone} />
                  <span className="font-medium text-foreground">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Section 5: Severity Chips & Badges */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icon icon={ShieldAlert} size="md" tone="primary" />
            5. Severity Chips & Badges
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <SeverityChip severity="Critical" count={33} />
            <SeverityChip severity="High" count={12} />
            <SeverityChip severity="Medium" count={48} />
            <SeverityChip severity="Low" count={5} />
            <SeverityChip severity="Info" count={2} />
          </div>

          <div className="flex flex-wrap items-center gap-6 pt-2">
            <SeverityChip severity="Critical" variant="dot" count={33} />
            <SeverityChip severity="High" variant="dot" count={12} />
            <SeverityChip severity="Medium" variant="dot" count={48} />
            <SeverityChip severity="Low" variant="dot" count={5} />
          </div>
        </CardContent>
      </Card>

      {/* Section 5: StatCards & Metric Grids */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <LayoutGrid className="h-4 w-4 text-primary" />
            5. Metric Cards & Tabular Figures
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <StatGrid columns={4}>
            <StatCard
              label="Critical Findings"
              value={33}
              icon={ShieldAlert}
              iconClass="bg-destructive/10 text-destructive"
              tone="critical"
              hint="Requires 24h SLA fix"
            />
            <StatCard
              label="High Priority"
              value={77}
              icon={AlertTriangle}
              iconClass="bg-chart-3/10 text-chart-3"
              tone="attention"
              hint="In violation of SLA"
            />
            <StatCard
              label="Active Targets"
              value={10}
              icon={GitBranch}
              iconClass="bg-primary/10 text-accent-strong"
              tone="default"
              hint="100% scan coverage"
            />
            <StatCard
              label="Remediated"
              value={158}
              icon={CheckCircle2}
              iconClass="bg-chart-5/10 text-chart-5"
              tone="positive"
              hint="Fixed this month"
            />
          </StatGrid>
        </CardContent>
      </Card>

      {/* Section 6: Progress Bars & Metric Meters */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4 text-primary" />
            6. Progress Indicators & Health Thresholds
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5 pt-4">
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-medium">Scan Coverage Score</span>
              <span className="font-mono tabular-nums font-semibold text-chart-5">100/100</span>
            </div>
            <ProgressBar value={100} size="md" />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-medium">SLA Compliance Health</span>
              <span className="font-mono tabular-nums font-semibold text-chart-3">51/100</span>
            </div>
            <ProgressBar value={51} size="md" />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-medium">Critical Risk Index</span>
              <span className="font-mono tabular-nums font-semibold text-destructive">25/100</span>
            </div>
            <ProgressBar value={25} size="md" />
          </div>
        </CardContent>
      </Card>

      {/* Section 7: Contextual Alert Banners */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <AlertTriangle className="h-4 w-4 text-primary" />
            7. Contextual Alert Banners
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 pt-4">
          <AlertBanner
            tone="critical"
            title="SLA Breach Detected"
            action={<Button size="sm" variant="destructive">Triage Now</Button>}
          >
            77 critical vulnerabilities have exceeded their SLA remediation window.
          </AlertBanner>

          <AlertBanner
            tone="warning"
            title="Unscanned Repositories"
            action={<Button size="sm" variant="outline">Run Scans</Button>}
          >
            2 newly onboarded repositories have never completed a dependency scan.
          </AlertBanner>

          <AlertBanner
            tone="positive"
            title="Zero False Positives"
          >
            All active rulesets evaluated with 98.5% confidence rating.
          </AlertBanner>
        </CardContent>
      </Card>

      {/* Section 8: Lifecycle & Task Status Badges */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4 text-primary" />
            8. Task & Lifecycle Status Badges
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status="running" label="Running (Semgrep)" />
            <StatusBadge status="completed" label="Scan Passed" />
            <StatusBadge status="failed" label="Scan Failed" />
            <StatusBadge status="blocked" label="PR Blocked" />
            <StatusBadge status="queued" label="Queued (Celery)" />
            <StatusBadge status="pending" label="Pending Approval" />
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <StatusBadge status="running" size="sm" />
            <StatusBadge status="completed" size="sm" />
            <StatusBadge status="failed" size="sm" />
            <StatusBadge status="blocked" size="sm" />
            <StatusBadge status="queued" size="sm" />
          </div>
        </CardContent>
      </Card>

      {/* Section 9: Universal Filter & Search Bar */}
      <Card>
        <CardHeader className="border-b pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Terminal className="h-4 w-4 text-primary" />
            9. Search & Filter Bar with Active Filter Pills
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          <FilterBar
            searchValue={demoSearch}
            onSearchChange={setDemoSearch}
            searchPlaceholder="Filter findings by CVE, rule, or repo..."
            activePills={activePills}
            onClearAllPills={() => setDemoPills([])}
            actions={
              <Button size="sm" variant="outline">
                Export Filtered
              </Button>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
