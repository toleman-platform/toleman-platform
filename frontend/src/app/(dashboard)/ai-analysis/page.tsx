"use client";

import { useEffect, useState } from "react";
import { api, Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SEVERITY_COLOR } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";

export default function AiAnalysisPage() {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.aiStatus().then((s) => setConfigured(s.configured));
    api.findings({ state: "Open", page_size: 500 }).then((r) => setFindings(r.items));
  }, []);

  async function analyze() {
    if (selected === null) return;
    setLoading(true);
    setError(null);
    setAnalysis(null);
    try {
      const res = await api.analyzeFinding(selected);
      setAnalysis(res.analysis);
    } catch (e) {
      setError(e instanceof Error ? e.message : "analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">AI Analysis</h1>
        <p className="text-sm text-muted-foreground">Claude-generated remediation guidance for a selected finding</p>
      </div>

      {configured === false && (
        <Card className="border-border bg-card">
          <CardContent className="px-4 py-3 text-sm text-muted-foreground">
            Not configured. Set <code className="text-foreground">ANTHROPIC_API_KEY</code> in the backend{" "}
            <code className="text-foreground">.env</code> to enable this feature.
          </CardContent>
        </Card>
      )}

      {configured && (
        <>
          <select
            className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
            value={selected ?? ""}
            onChange={(e) => setSelected(Number(e.target.value))}
          >
            <option value="" disabled>
              Select an open finding...
            </option>
            {findings.map((f) => (
              <option key={f.id} value={f.id}>
                [{f.severity}] {f.title} ({f.file_path})
              </option>
            ))}
          </select>

          <Button onClick={analyze} disabled={selected === null || loading} className="self-start">
            {loading ? "Analyzing..." : "Analyze with Claude"}
          </Button>

          {error && <p className="text-sm text-destructive">{error}</p>}

          {analysis && (
            <Card className="border-border bg-card">
              <CardContent className="px-4 py-4">
                {selected !== null && (
                  <Badge variant="outline" className={SEVERITY_COLOR[findings.find((f) => f.id === selected)?.severity ?? "Low"]}>
                    {findings.find((f) => f.id === selected)?.severity}
                  </Badge>
                )}
                <p className="mt-3 whitespace-pre-wrap text-sm text-foreground">{analysis}</p>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
