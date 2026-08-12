"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";

const TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"];

export function ScanButtons({ targetId }: { targetId: number }) {
  const router = useRouter();
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  async function run(tool: string) {
    setRunning(tool);
    setResult(null);
    try {
      const res = await api.runScan(targetId, tool);
      if ("error" in res) {
        setResult(`${tool}: ${res.error}`);
      } else {
        setResult(`${tool}: ${res.ingested} findings ingested`);
        router.refresh();
      }
    } catch (err) {
      setResult(`${tool}: ${err instanceof Error ? err.message : "failed"}`);
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="space-y-2 text-right">
      <div className="flex gap-2">
        {TOOLS.map((tool) => (
          <Button key={tool} size="sm" variant="outline" disabled={running !== null} onClick={() => run(tool)}>
            {running === tool ? "Running..." : `Run ${tool}`}
          </Button>
        ))}
      </div>
      {result && <p className="text-xs text-muted-foreground">{result}</p>}
    </div>
  );
}
