"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { Button } from "@/components/ui/button";

const TOOLS = ["semgrep", "gitleaks", "trivy", "trivy-license", "gosec"];

export function ScanButtons({ targetId }: { targetId: number }) {
  const router = useRouter();
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const cancelPollRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    // Stop polling if the component unmounts (e.g. navigating away) mid-scan.
    return () => cancelPollRef.current?.();
  }, []);

  async function run(tool: string) {
    setRunning(tool);
    setResult(null);
    cancelPollRef.current?.();
    try {
      // POST /api/scans/run now dispatches a Celery task and returns
      // immediately with status: "running" (#59) instead of blocking until
      // the clone+scan finishes -- poll GET /api/scans/{scan_id} until it's
      // done.
      const res = await api.runScan(targetId, tool);
      if ("error" in res) {
        setResult(`${tool}: ${res.error}`);
        setRunning(null);
        return;
      }

      const scanId = res.scan_id;
      cancelPollRef.current = pollUntilSettled(
        async () => {
          const scan = await api.getScan(scanId);
          // Normalize the { error } shape (e.g. scan row not found) into a
          // "failed" status so pollUntilSettled's status-based loop can
          // still stop -- polling would otherwise spin forever.
          if ("error" in scan) return { status: "failed" as const, message: scan.error };
          return { status: scan.status, findings_count: scan.findings_count };
        },
        (scan) => {
          if (scan.status === "completed") {
            setResult(`${tool}: ${scan.findings_count} findings ingested`);
            setRunning(null);
            router.refresh();
          } else if (scan.status === "failed") {
            setResult(`${tool}: ${scan.message ?? "scan failed"}`);
            setRunning(null);
          }
        },
        {
          onError: (err) => {
            setResult(`${tool}: ${err instanceof Error ? err.message : "failed"}`);
            setRunning(null);
          },
        },
      );
    } catch (err) {
      setResult(`${tool}: ${err instanceof Error ? err.message : "failed"}`);
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
