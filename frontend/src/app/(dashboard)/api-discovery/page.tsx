"use client";

import { useEffect, useState } from "react";
import { api, Target, Endpoint } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";

export default function ApiDiscoveryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  async function run() {
    if (targetId === null) return;
    setRunning(true);
    setError(null);
    setEndpoints(null);
    try {
      const res = await api.runDiscovery(targetId);
      setEndpoints(res.endpoints);
    } catch (e) {
      setError(e instanceof Error ? e.message : "discovery failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">API Discovery</h1>
        <p className="text-sm text-muted-foreground">
          Static route extraction over the target&apos;s source (Flask/FastAPI/Express/Gin/Django/Spring patterns) —
          real grep matches with file:line provenance, not an inferred/mocked inventory.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />
        <Button onClick={run} disabled={running || targetId === null}>
          {running ? "Scanning..." : "Run Discovery"}
        </Button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {endpoints && (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">{endpoints.length} endpoints found</p>
          {endpoints.map((e, i) => (
            <Card key={i} className="border-border bg-card">
              <CardContent className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-3">
                  <Badge variant="outline">{e.method}</Badge>
                  <span className="font-mono text-sm text-foreground">{e.route}</span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {e.framework} · {e.file}:{e.line}
                </span>
              </CardContent>
            </Card>
          ))}
          {endpoints.length === 0 && <p className="text-sm text-muted-foreground">No routes matched known framework patterns.</p>}
        </div>
      )}
    </div>
  );
}
