"use client";

import { useState } from "react";
import { api, type Target } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { PageHeader } from "@/components/ui/page-header";
import { AlertBanner } from "@/components/ui/alert-banner";
import {
  DocGenField,
  DocGenToggle,
  DocumentGeneratorPanel,
  WhatsIncludedCard,
} from "@/components/features/intelligence";

type ExportFormat = "csv" | "pdf";

export default function ReportsPage() {
  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const targets = targetsData ?? [];
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const targetId = selectedTargetId ?? (targets.length > 0 ? ALL_TARGETS : null);
  const setTargetId = setSelectedTargetId;
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDownload, setLastDownload] = useState<string | null>(null);

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
      <PageHeader
        title="Compliance Reports"
        description="Audit-ready posture export built from live workspace data, finding counts by severity and state, SLA age, scan coverage, and SBOM summary."
      />

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

            {error && (
              <AlertBanner tone="critical" className="mt-2">
                {error}
              </AlertBanner>
            )}
            {!error && lastDownload && (
              <AlertBanner tone="positive" className="mt-2" title="Report Exported">
                Downloaded <span className="font-mono font-medium">{lastDownload}</span>
              </AlertBanner>
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
