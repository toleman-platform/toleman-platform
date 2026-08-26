"use client";

import { useEffect, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { api, Target } from "@/lib/api";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import {
  DocGenField,
  DocGenToggle,
  DocumentGeneratorPanel,
  WhatsIncludedCard,
} from "@/components/document-generator-panel";

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
      const filename = `toleman-posture-report-${scopeLabel.replace(/\s+/g, "-")}-${dateSlug}.${format}`;
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
          Audit-ready posture export built from your live workspace data,
          finding counts by severity and state, open-finding SLA age, scan
          coverage, and SBOM summary. Every figure reflects your current
          findings and scans, generated fresh each time you run it.
        </p>
      </div>

      <DocumentGeneratorPanel
        layout="inline"
        steps={[
          <DocGenField key="scope" label="Scope">
            <TargetPicker targets={targets} value={targetId} onChange={setTargetId} allowAll />
          </DocGenField>,
          <DocGenField key="format" label="Format">
            <DocGenToggle
              options={[
                { value: "csv", label: "CSV" },
                { value: "pdf", label: "PDF" },
              ]}
              value={format}
              onChange={(v) => setFormat(v as ExportFormat)}
            />
          </DocGenField>,
        ]}
        generateLabel="Generate Report"
        onGenerate={generate}
        generating={exporting}
        generateDisabled={targetId === null}
        extra={
          <div className="basis-full">
            <p className="text-xs text-muted-foreground">
              Scope: <span className="font-medium text-foreground">{scopeLabel}</span>
              {targetId === ALL_TARGETS
                ? ", every target in the platform"
                : currentTarget
                  ? `, default branch (${currentTarget.default_branch})`
                  : ""}
            </p>

            {error && <p className="mt-2 text-sm text-destructive">{error}</p>}
            {!error && lastDownload && (
              <p className="mt-2 flex items-center gap-1.5 text-sm text-success">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                Downloaded <span className="font-mono text-foreground">{lastDownload}</span>
              </p>
            )}
          </div>
        }
      />

      <WhatsIncludedCard
        items={[
          "Finding counts by severity and triage state, per target and totals",
          "Open-finding age / SLA buckets (0-7d, 8-30d, 31-90d, 90d+)",
          "Scan history and coverage; latest run per tool, per target",
          "SBOM component summary per target (when SBOM data has been generated)",
        ]}
        footnote="All figures reflect each target's default branch, matching the Posture Dashboard."
      />
    </div>
  );
}
