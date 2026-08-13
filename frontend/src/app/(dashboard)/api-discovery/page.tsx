"use client";

import { useCallback, useEffect, useState } from "react";
import { api, Target, Endpoint } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";
import { SkeletonList } from "@/components/ui/skeleton";

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
      const res = await api.getDiscoveredEndpoints(id);
      setEndpoints(res.endpoints);
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
    setRunning(true);
    setError(null);
    try {
      const res = await api.runDiscovery(targetId);
      setEndpoints(res.endpoints);
      setScanSummary({ new_count: res.new_count });
    } catch (e) {
      setError(e instanceof Error ? e.message : "discovery failed");
    } finally {
      setRunning(false);
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
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">{endpoints.length} endpoints found</p>
          {endpoints.map((e) => (
            <Card key={e.id} className="border-border bg-card">
              <CardContent className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-3">
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
            <p className="text-sm text-muted-foreground">
              No routes matched known framework patterns yet. Run discovery to scan this target.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
