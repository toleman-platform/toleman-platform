"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { SCAN_TOOLS } from "@/lib/scan-tools";
import { Button } from "@/components/ui/button";
import { ScanProgress } from "@/components/scan-status";
import { useScanRun } from "@/hooks/use-scan-run";

const TOOLS = SCAN_TOOLS;

export function ScanButtons({ targetId }: { targetId: number }) {
  const router = useRouter();
  const [tool, setTool] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  // Issue #212: this used to say "Running..." on one button and nothing
  // else -- no indication of how long the scan had been going, whether it
  // had started at all, or (on failure) why it stopped. The polling and the
  // countdown live in useScanRun now, so this component only decides what to
  // show and what to do when the run settles.
  //
  // `toolRef` rather than the `tool` state: these callbacks are invoked from
  // the poll timer, which closed over whichever render created it.
  const toolRef = useRef<string | null>(null);
  const scan = useScanRun({
    onCompleted: (findingsCount) => {
      setResult(`${toolRef.current}: ${findingsCount} findings ingested`);
      setTool(null);
      // New findings only appear on a server render, so the page is
      // refreshed when the scan actually lands -- not when it was dispatched,
      // which is what the old version effectively did.
      router.refresh();
    },
    onFailed: (message) => {
      setResult(`${toolRef.current}: ${message}`);
      setTool(null);
    },
  });

  async function run(nextTool: string) {
    setTool(nextTool);
    toolRef.current = nextTool;
    setResult(null);
    scan.reset();
    try {
      const res = await api.runScan(targetId, nextTool);
      if ("error" in res) {
        // A rejected dispatch (rate limit, unsupported tool) never produces
        // a scan id, so it is reported through the same failure path rather
        // than a second one that could word it differently.
        scan.fail(res.error);
        return;
      }
      scan.track(res.scan_id);
    } catch (err) {
      scan.fail(err instanceof Error ? err.message : "failed");
    }
  }

  const busy = tool !== null;

  return (
    <div className="space-y-2 text-right">
      {/* Wraps: #186 and #189 took this from 5 tools to 7, and a single
          non-wrapping row squeezed the target header beside it (#197). */}
      <div className="flex flex-wrap justify-end gap-2">
        {TOOLS.map((t) => (
          <Button key={t} size="sm" variant="outline" disabled={busy} onClick={() => run(t)}>
            {tool === t ? "Running..." : `Run ${t}`}
          </Button>
        ))}
      </div>

      {busy && scan.phase && (
        <div className="flex justify-end">
          <ScanProgress
            phase={scan.phase}
            tool={tool ?? undefined}
            elapsedSeconds={scan.elapsedSeconds}
            etaSeconds={scan.etaSeconds}
            error={scan.error}
          />
        </div>
      )}

      {result && <p className="text-xs text-muted-foreground">{result}</p>}
    </div>
  );
}
