"use client";

import { useEffect, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { api, Target } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { cn } from "@/lib/utils";

type ExportFormat = "csv" | "pdf";

export default function ReportsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDownload, setLastDownload] = useState<string | null>(null);

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      setTargetId(ts.length > 0 ? ALL_TARGETS : null);
    });
  }, []);

  const currentTarget = targets.find((t) => t.id === targetId);
  const scopeLabel =
    targetId === ALL_TARGETS ? "org-wide" : (currentTarget?.name ?? "target");

  async function generate() {
    if (targetId === null) return;
    setExporting(true);
    setError(null);
    setLastDownload(null);
    try {
      const blob = await api.exportPostureReport(targetId, format);
      const url = URL.createObjectURL(blob);
      const dateSlug = new Date().toISOString().slice(0, 10);
      const filename = `osp-posture-report-${scopeLabel.replace(/\s+/g, "-")}-${dateSlug}.${format}`;
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setLastDownload(filename);
    } catch (e) {
      setError(e instanceof Error ? e.message : "report generation failed");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          Compliance Reports
        </h1>
        <p className="text-sm text-muted-foreground">
          Real audit-evidence posture report generated from live data —
          finding counts by severity/state, open-finding age (SLA), scan
          history/coverage, and SBOM summary. No mocked or placeholder
          content; every figure is pulled straight from the database at
          generation time.
        </p>
      </div>

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-6 py-5">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Scope
              </label>
              <TargetPicker
                targets={targets}
                value={targetId}
                onChange={setTargetId}
                allowAll
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Format
              </label>
              <div className="flex gap-1 rounded-md border border-input bg-secondary p-1">
                {(["csv", "pdf"] as ExportFormat[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    className={cn(
                      "rounded px-3 py-1.5 text-sm font-medium uppercase transition-colors",
                      format === f
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <Button onClick={generate} disabled={exporting || targetId === null}>
              {exporting ? "Generating..." : "Generate Report"}
            </Button>
          </div>

          <p className="text-xs text-muted-foreground">
            Scope: <span className="font-medium text-foreground">{scopeLabel}</span>
            {targetId === ALL_TARGETS
              ? " — every target in the platform"
              : currentTarget
                ? ` — default branch (${currentTarget.default_branch})`
                : ""}
          </p>

          {error && <p className="text-sm text-destructive">{error}</p>}
          {!error && lastDownload && (
            <p className="flex items-center gap-1.5 text-sm text-success">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              Downloaded <span className="font-mono text-foreground">{lastDownload}</span>
            </p>
          )}
        </CardContent>
      </Card>

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-2 px-6 py-5">
          <h2 className="text-sm font-semibold text-foreground">
            What&apos;s included
          </h2>
          <ul className="list-disc pl-5 text-sm text-muted-foreground">
            <li>Finding counts by severity and triage state, per target and totals</li>
            <li>Open-finding age / SLA buckets (0-7d, 8-30d, 31-90d, 90d+)</li>
            <li>Scan history and coverage — latest run per tool, per target</li>
            <li>SBOM component summary per target (when SBOM data has been generated)</li>
          </ul>
          <p className="text-xs text-muted-foreground">
            All figures reflect each target&apos;s default branch, matching the
            Posture Dashboard.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
