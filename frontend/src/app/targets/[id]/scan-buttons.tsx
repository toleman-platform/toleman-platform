"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

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
    <div className="text-right space-y-2">
      <div className="flex gap-2">
        {TOOLS.map((tool) => (
          <button
            key={tool}
            onClick={() => run(tool)}
            disabled={running !== null}
            className="text-xs border border-neutral-700 rounded px-3 py-1.5 hover:border-neutral-500 disabled:opacity-50"
          >
            {running === tool ? "Running..." : `Run ${tool}`}
          </button>
        ))}
      </div>
      {result && <p className="text-xs text-neutral-400">{result}</p>}
    </div>
  );
}
