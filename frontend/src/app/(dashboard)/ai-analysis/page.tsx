"use client";

import { useEffect, useState } from "react";
import { api, Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SEVERITY_COLOR } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

export default function AiAnalysisPage() {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [provider, setProvider] = useState<"anthropic" | "openai_compatible">("anthropic");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.aiStatus().then((s) => {
      setConfigured(s.configured);
      setProvider(s.provider);
    });
    api.findings({ state: "Open", page_size: 500 }).then((r) => setFindings(r.items));
  }, []);

  const providerLabel = provider === "openai_compatible" ? "your configured model" : "Claude";

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
        <p className="text-sm text-muted-foreground">{providerLabel}-generated remediation guidance for a selected finding</p>
      </div>

      {configured === null && (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-9 w-full max-w-md" />
          <Skeleton className="h-9 w-32" />
        </div>
      )}

      {configured === false && (
        <Card className="border-border bg-card">
          <CardContent className="px-4 py-3 text-sm text-muted-foreground">
            Not configured. Set an AI provider in <code className="text-foreground">Admin &gt; Global Integrations</code>{" "}
            (Anthropic API key, or a self-hosted/OpenAI-compatible endpoint like Ollama or Kimi) to enable this
            feature.
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
            {loading ? "Analyzing..." : `Analyze with ${providerLabel}`}
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
