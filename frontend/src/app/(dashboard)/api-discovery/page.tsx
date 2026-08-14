"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, Target, Endpoint, ScanRun } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { Globe } from "lucide-react";

const NEW_BADGE_COLOR = "border-chart-5/20 bg-chart-5/10 text-chart-5";

function formatSince(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `since ${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`;
}

export default function ApiDiscoveryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Only meaningful relative to a scan just triggered in this session -- the
  // plain GET on load always reports is_new: false, so we don't show the
  // "New" column at all until a POST has completed here.
  const [scanSummary, setScanSummary] = useState<{ new_count: number } | null>(null);
  const cancelPollRef = useRef<(() => void) | null>(null);

  // Issue #72: Active API Scanning against the endpoints listed above.
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [apiScanRunning, setApiScanRunning] = useState(false);
  const [apiScanError, setApiScanError] = useState<string | null>(null);
  const [lastApiScan, setLastApiScan] = useState<ScanRun | null>(null);
  const cancelApiScanPollRef = useRef<(() => void) | null>(null);
  const currentTarget = targets.find((t) => t.id === targetId) ?? null;

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  useEffect(() => {
    // Stop polling if the component unmounts (e.g. navigating away) mid-run.
    return () => {
      cancelPollRef.current?.();
      cancelApiScanPollRef.current?.();
    };
  }, []);

  const loadPersisted = useCallback(async (id: number) => {
    setLoading(true);
    setError(null);
    setScanSummary(null);
    setSelected(new Set());
    setApiScanError(null);
    try {
      const [res, latest] = await Promise.all([api.getDiscoveredEndpoints(id), api.getLatestApiScan(id)]);
      setEndpoints(res.endpoints);
      setLastApiScan(latest.scan);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load discovered endpoints");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (targetId !== null) loadPersisted(targetId);
  }, [targetId, loadPersisted]);

  async function run() {
    if (targetId === null) return;
    const runTargetId = targetId;
    setRunning(true);
    setError(null);
    cancelPollRef.current?.();
    try {
      // POST /api/discovery/{target_id} now dispatches a Celery task and
      // returns immediately with status: "running" (#59) instead of
      // blocking until the clone+grep finishes -- poll
      // GET /api/discovery/{target_id}/runs/{run_id} until it's done.
      const dispatch = await api.runDiscovery(runTargetId);
      cancelPollRef.current = pollUntilSettled(
        () => api.getDiscoveryRun(runTargetId, dispatch.run_id),
        (run) => {
          if (run.status === "completed") {
            setEndpoints(run.endpoints ?? []);
            setScanSummary({ new_count: run.new_count });
            setRunning(false);
          } else if (run.status === "failed") {
            setError(run.error || "discovery failed");
            setRunning(false);
          }
        },
        {
          onError: (e) => {
            setError(e instanceof Error ? e.message : "discovery failed");
            setRunning(false);
          },
        },
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "discovery failed");
      setRunning(false);
    }
  }

  function toggleEndpoint(id: number, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelected(checked && endpoints ? new Set(endpoints.map((e) => e.id)) : new Set());
  }

  async function runApiScan() {
    if (targetId === null) return;
    const scanTargetId = targetId;
    setApiScanRunning(true);
    setApiScanError(null);
    cancelApiScanPollRef.current?.();
    try {
      // POST /api/api-scan/{target_id} dispatches a Celery task (nuclei
      // against already-discovered endpoints) and returns immediately
      // (#72, same async pattern as runScan/runDiscovery) -- poll
      // GET /api/scans/{scan_id} until status leaves "running".
      const dispatch = await api.runApiScan(scanTargetId, selected.size > 0 ? Array.from(selected) : undefined);
      cancelApiScanPollRef.current = pollUntilSettled(
        async () => {
          const scan = await api.getScan(dispatch.scan_id);
          // Normalize the { error } shape (e.g. scan row not found) into a
          // "failed" status so pollUntilSettled's status-based loop can
          // still stop -- polling would otherwise spin forever. Same
          // pattern as scan-buttons.tsx.
          if ("error" in scan) return { status: "failed" as const, scan: null, message: scan.error };
          return { status: scan.status, scan, message: null };
        },
        (result) => {
          if (result.status === "completed" || result.status === "failed") {
            if (result.scan) setLastApiScan(result.scan);
            else if (result.message) setApiScanError(result.message);
            setApiScanRunning(false);
          }
        },
        {
          onError: (e) => {
            setApiScanError(e instanceof Error ? e.message : "active scan failed");
            setApiScanRunning(false);
          },
        },
      );
    } catch (e) {
      setApiScanError(e instanceof Error ? e.message : "active scan failed to start");
      setApiScanRunning(false);
    }
  }

  const showBusy = loading || running;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">API Discovery</h1>
        <p className="text-sm text-muted-foreground">
          Static route extraction over the target&apos;s source (Flask/FastAPI/Express/Gin/Django/Spring patterns) —
          real grep matches with file:line provenance, not an inferred/mocked inventory. Results are persisted, so
          this view reflects the last scan even after a reload.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />
        <Button onClick={run} disabled={running || targetId === null}>
          {running ? "Scanning..." : "Run Discovery"}
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {!error && scanSummary && (
        <p className="text-sm text-foreground">
          {scanSummary.new_count > 0
            ? `${scanSummary.new_count} new endpoint${scanSummary.new_count === 1 ? "" : "s"} found`
            : "No new endpoints"}
        </p>
      )}

      {showBusy && <SkeletonList count={3} />}

      {!showBusy && endpoints && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">{endpoints.length} endpoints found</p>
            {endpoints.length > 0 && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  aria-label="Select all endpoints"
                  className="h-4 w-4 accent-primary"
                  checked={selected.size > 0 && selected.size === endpoints.length}
                  onChange={(e) => toggleAll(e.target.checked)}
                />
                <span>Select all</span>
              </div>
            )}
          </div>

          {endpoints.length > 0 && (
            <div className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-secondary/50 p-3">
              <span className="text-xs font-medium text-foreground">
                {selected.size > 0 ? `${selected.size} endpoint${selected.size === 1 ? "" : "s"} selected` : "Active API Scanning"}
              </span>
              <Button
                size="sm"
                className="h-7 text-xs"
                onClick={runApiScan}
                disabled={apiScanRunning || !currentTarget?.api_base_url}
                aria-label={selected.size > 0 ? `Scan ${selected.size} selected endpoints for vulnerabilities` : "Scan all discovered endpoints for vulnerabilities"}
              >
                {apiScanRunning
                  ? "Scanning..."
                  : selected.size > 0
                    ? `Scan ${selected.size} selected for vulnerabilities`
                    : "Scan all for vulnerabilities"}
              </Button>
              {!currentTarget?.api_base_url && (
                <span className="text-xs text-muted-foreground">
                  Set this target&apos;s API base URL on its{" "}
                  <Link href={`/targets/${targetId}`} className="underline">
                    detail page
                  </Link>{" "}
                  first.
                </span>
              )}
            </div>
          )}

          {apiScanError && <p className="text-xs text-destructive">{apiScanError}</p>}

          {lastApiScan && !apiScanRunning && (
            <p className="text-xs text-foreground">
              {lastApiScan.status === "completed"
                ? `Last active scan: ${lastApiScan.findings_count} finding${lastApiScan.findings_count === 1 ? "" : "s"} (tool=api-scan)`
                : lastApiScan.status === "failed"
                  ? "Last active scan failed."
                  : `Last active scan: ${lastApiScan.status}`}
              {lastApiScan.status === "completed" && lastApiScan.findings_count > 0 && targetId !== null && (
                <>
                  {" — "}
                  <Link href={`/targets/${targetId}`} className="underline">
                    view findings
                  </Link>
                </>
              )}
            </p>
          )}

          {endpoints.map((e) => (
            <Card key={e.id} className="border-border bg-card">
              <CardContent className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    aria-label={`Select ${e.method} ${e.route}`}
                    className="h-4 w-4 accent-primary"
                    checked={selected.has(e.id)}
                    onChange={(ev) => toggleEndpoint(e.id, ev.target.checked)}
                  />
                  <Badge variant="outline">{e.method}</Badge>
                  <span className="font-mono text-sm text-foreground">{e.route}</span>
                  {scanSummary && e.is_new && (
                    <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${NEW_BADGE_COLOR}`}>
                      New
                    </Badge>
                  )}
                </div>
                <span className="text-xs text-muted-foreground">
                  {e.framework} · {e.file}:{e.line} · {formatSince(e.first_seen)}
                </span>
              </CardContent>
            </Card>
          ))}
          {endpoints.length === 0 && (
            <EmptyState
              icon={Globe}
              title="No routes discovered yet"
              description="Run discovery to scan this target's codebase for API routes."
              action={
                <Button size="sm" onClick={run} disabled={running || targetId === null}>
                  {running ? "Scanning..." : "Run Discovery"}
                </Button>
              }
            />
          )}
        </div>
      )}
    </div>
  );
}
