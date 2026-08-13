"use client";

import { useCallback, useEffect, useState } from "react";
import { api, Target, SbomComponent, Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";
import { SkeletonList } from "@/components/ui/skeleton";
import { FindingsList } from "@/components/findings-list";
import { cn } from "@/lib/utils";

const NEW_BADGE_COLOR = "border-chart-5/20 bg-chart-5/10 text-chart-5";

function formatSince(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `since ${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`;
}

type Tab = "components" | "vulnerabilities";

export default function SbomPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [components, setComponents] = useState<SbomComponent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Only meaningful relative to a scan just triggered in this session -- the
  // plain GET on load always reports is_new: false, so we don't show the
  // "New" badge at all until a POST has completed here (same convention as
  // the API Discovery page).
  const [scanSummary, setScanSummary] = useState<{ new_count: number } | null>(null);
  const [tab, setTab] = useState<Tab>("components");
  const [exporting, setExporting] = useState(false);

  const [ossFindings, setOssFindings] = useState<Finding[] | null>(null);
  const [ossTotal, setOssTotal] = useState(0);
  const [ossLoading, setOssLoading] = useState(false);

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  const loadPersisted = useCallback(async (id: number) => {
    setLoading(true);
    setError(null);
    setScanSummary(null);
    try {
      const res = await api.getSbom(id);
      setComponents(res.components);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load SBOM");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadOssFindings = useCallback(async (id: number) => {
    setOssLoading(true);
    try {
      // Trivy's existing CVE scan already produces real Finding rows with
      // tool="trivy" and a populated cve_id -- OSS/dependency vulnerabilities
      // aren't a new concept, so we just filter the existing findings API
      // rather than standing up a parallel endpoint.
      const res = await api.findings({ target_id: id, tool: "trivy", page_size: 500 });
      setOssFindings(res.items.filter((f) => !!f.cve_id));
      setOssTotal(res.items.filter((f) => !!f.cve_id).length);
    } catch {
      setOssFindings([]);
      setOssTotal(0);
    } finally {
      setOssLoading(false);
    }
  }, []);

  useEffect(() => {
    if (targetId !== null) {
      loadPersisted(targetId);
      loadOssFindings(targetId);
    }
  }, [targetId, loadPersisted, loadOssFindings]);

  async function run() {
    if (targetId === null) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.generateSbom(targetId);
      setComponents(res.components);
      setScanSummary({ new_count: res.new_count });
    } catch (e) {
      setError(e instanceof Error ? e.message : "SBOM generation failed");
    } finally {
      setRunning(false);
    }
  }

  async function exportJson() {
    if (targetId === null) return;
    setExporting(true);
    setError(null);
    try {
      const blob = await api.exportSbom(targetId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom-${currentTarget?.name ?? targetId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "SBOM export failed");
    } finally {
      setExporting(false);
    }
  }

  const showBusy = loading || running;
  const currentTarget = targets.find((t) => t.id === targetId);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">SBOM & OSS Vulnerabilities</h1>
        <p className="text-sm text-muted-foreground">
          Real CycloneDX SBOM generated from the target&apos;s dependency manifests (requirements.txt, package.json,
          go.mod, ...) via <code className="rounded bg-secondary px-1 py-0.5 text-xs">trivy fs --format cyclonedx</code> —
          no mocked or inferred data. Results are persisted, so this view reflects the last generation even after a
          reload.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />
        <Button onClick={run} disabled={running || targetId === null}>
          {running ? "Generating..." : "Generate SBOM"}
        </Button>
        <Button
          variant="outline"
          onClick={exportJson}
          disabled={exporting || targetId === null || !components || components.length === 0}
        >
          {exporting ? "Exporting..." : "Export SBOM (JSON)"}
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {!error && scanSummary && (
        <p className="text-sm text-foreground">
          {scanSummary.new_count > 0
            ? `${scanSummary.new_count} new component${scanSummary.new_count === 1 ? "" : "s"} found`
            : "No new components"}
        </p>
      )}

      <div className="flex gap-1 border-b border-border">
        <button
          onClick={() => setTab("components")}
          className={cn(
            "px-3 py-2 text-sm font-medium transition-colors",
            tab === "components"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          Components{components ? ` (${components.length})` : ""}
        </button>
        <button
          onClick={() => setTab("vulnerabilities")}
          className={cn(
            "px-3 py-2 text-sm font-medium transition-colors",
            tab === "vulnerabilities"
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          OSS Vulnerabilities{ossFindings ? ` (${ossTotal})` : ""}
        </button>
      </div>

      {tab === "components" && (
        <>
          {showBusy && <SkeletonList count={3} />}
          {!showBusy && components && (
            <div className="flex flex-col gap-2">
              <p className="text-sm text-muted-foreground">{components.length} components found</p>
              {components.map((c) => (
                <Card key={c.id} className="border-border bg-card">
                  <CardContent className="flex items-center justify-between px-4 py-2.5">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm text-foreground">{c.name}</span>
                      <Badge variant="outline">{c.version}</Badge>
                      {scanSummary && c.is_new && (
                        <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${NEW_BADGE_COLOR}`}>
                          New
                        </Badge>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {c.package_type} · {c.purl} · {formatSince(c.first_seen)}
                    </span>
                  </CardContent>
                </Card>
              ))}
              {components.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No components recorded yet. Generate an SBOM to scan this target&apos;s dependency manifests.
                </p>
              )}
            </div>
          )}
        </>
      )}

      {tab === "vulnerabilities" && (
        <>
          {ossLoading && <SkeletonList count={3} />}
          {!ossLoading && ossFindings && (
            <FindingsList
              findings={ossFindings}
              total={ossTotal}
              page={1}
              pageSize={Math.max(ossTotal, 1)}
              targets={currentTarget ? [currentTarget] : targets}
            />
          )}
        </>
      )}
    </div>
  );
}
