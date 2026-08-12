"use client";

import { useState } from "react";
import { api, PrGuardrailScanResult } from "@/lib/api";
import { SEVERITY_COLOR } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const SCAN_STATUS_COLOR: Record<string, string> = {
  passed: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  blocked: "border-destructive/20 bg-destructive/10 text-destructive",
  error: "border-border bg-muted text-muted-foreground",
};

export function PrScanAction({ targetId, prNumber }: { targetId: number; prNumber: number }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PrGuardrailScanResult | null>(null);
  const [expanded, setExpanded] = useState(false);

  async function runScan() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.runPrGuardrailScan(targetId, prNumber);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "scan failed");
    } finally {
      setLoading(false);
    }
  }

  if (!result) {
    return (
      <div className="flex flex-col items-end gap-1">
        <Button size="sm" variant="outline" disabled={loading} onClick={runScan} className="h-7 text-xs">
          {loading ? "Scanning..." : "Scan This PR"}
        </Button>
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className={SCAN_STATUS_COLOR[result.status] || "text-muted-foreground"}>
          {result.status}
        </Badge>
        {result.new_findings_count > 0 && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-xs text-muted-foreground underline hover:text-foreground"
          >
            {result.new_findings_count} new finding{result.new_findings_count === 1 ? "" : "s"}
            {expanded ? " (hide)" : " (show)"}
          </button>
        )}
        {result.new_findings_count === 0 && (
          <span className="text-xs text-muted-foreground">no new findings</span>
        )}
      </div>

      {expanded && result.new_findings.length > 0 && (
        <div className="mt-1 flex w-full max-w-md flex-col gap-1 rounded-md border border-border bg-secondary p-2">
          {result.new_findings.map((f, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <Badge variant="outline" className={`shrink-0 ${SEVERITY_COLOR[f.severity] || "text-muted-foreground"}`}>
                {f.severity}
              </Badge>
              <span className="min-w-0 flex-1 truncate text-foreground">{f.title}</span>
              <span className="shrink-0 text-muted-foreground">
                {f.file_path}
                {f.line_start ? `:${f.line_start}` : ""}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
