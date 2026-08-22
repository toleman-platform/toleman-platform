"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { SCAN_TOOLS } from "@/lib/scan-tools";
import { Button } from "@/components/ui/button";
import { ScanProgress } from "@/components/scan-status";
import { useScanRun } from "@/hooks/use-scan-run";
import { useActiveScans } from "@/hooks/use-active-scans";

const TOOLS = SCAN_TOOLS;

export function ScanButtons({ targetId, workspaceId }: { targetId: number; workspaceId: number }) {
  const router = useRouter();
  const [tool, setTool] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  // (#232) on_demand_scan assignments now actually gate execution
  // server-side (POST /api/scans/run refuses a disabled tool). A button
  // that is clickable but always 400s is worse than no button -- so the
  // same assignment that gates the backend also decides which buttons
  // render. Starts as the full static list (never fewer options flash
  // before the real answer loads) and narrows once assignments resolve;
  // a fetch failure leaves every button visible rather than hiding tools a
  // user might actually be allowed to run.
  const [enabledTools, setEnabledTools] = useState<readonly string[]>(TOOLS);
  useEffect(() => {
    let cancelled = false;
    api
      .toolAssignments(workspaceId)
      .then((rows) => {
        if (cancelled) return;
        const disabled = new Set(rows.filter((r) => !r.on_demand_scan).map((r) => r.tool));
        setEnabledTools(TOOLS.filter((t) => !disabled.has(t)));
      })
      .catch(() => {
        // Leave the full list visible -- see comment above.
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  // Issue #212: this used to say "Running..." on one button and nothing
  // else -- no indication of how long the scan had been going, whether it
  // had started at all, or (on failure) why it stopped. The polling and the
  // countdown live in useScanRun now, so this component only decides what to
  // show and what to do when the run settles.
  //
  // `toolRef` rather than the `tool` state: these callbacks are invoked from
  // the poll timer, which closed over whichever render created it.
  const toolRef = useRef<string | null>(null);
  const { activeScans, refresh: refreshActiveScans } = useActiveScans();
  const scan = useScanRun({
    onCompleted: (findingsCount) => {
      setResult(`${toolRef.current}: ${findingsCount} findings ingested`);
      setTool(null);
      refreshActiveScans();
      // New findings only appear on a server render, so the page is
      // refreshed when the scan actually lands -- not when it was dispatched,
      // which is what the old version effectively did.
      router.refresh();
    },
    onFailed: (message) => {
      setResult(`${toolRef.current}: ${message}`);
      setTool(null);
      refreshActiveScans();
    },
  });

  // A refresh used to lose all of this: useScanRun only ever knows about a
  // scan this component instance dispatched itself, so reloading the page --
  // or the scan having been started from the Scans page's bulk trigger, or
  // another browser tab -- left a scan running server-side with nothing on
  // screen saying so. useActiveScans polls GET /api/scans/active, the server
  // truth, so anything already running shows up here too and survives a
  // refresh because it is re-derived from the server on every mount, not
  // carried in component state.
  const running = activeScans[String(targetId)] ?? [];
  // Excludes whichever scan this component itself just dispatched -- that
  // one is already shown below via `scan` (full queued/running lifecycle,
  // completion callback, failure reason). Showing it twice would be showing
  // the same running scan under two different progress bars.
  const externallyRunning = running.filter((r) => r.tool !== tool);

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
  // Concurrent scans of different tools against the same target are safe --
  // each gets its own scan-scoped clone directory (runner.clone_repo is
  // explicit about this: "so a concurrent scan" can't corrupt it) -- so only
  // the specific tool that is actually running gets disabled, not every
  // button the moment any one scan starts.
  const runningTools = new Set([...(busy ? [tool] : []), ...running.map((r) => r.tool)]);

  return (
    <div className="space-y-2 text-right">
      {/* Wraps: #186 and #189 took this from 5 tools to 7, and a single
          non-wrapping row squeezed the target header beside it (#197). */}
      <div className="flex flex-wrap justify-end gap-2">
        {enabledTools.map((t) => (
          <Button key={t} size="sm" variant="outline" disabled={runningTools.has(t)} onClick={() => run(t)}>
            {runningTools.has(t) ? "Running..." : `Run ${t}`}
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

      {externallyRunning.map((r) => (
        <div key={r.scan_id} className="flex justify-end">
          <ScanProgress phase="running" tool={r.tool} elapsedSeconds={r.elapsed_seconds} etaSeconds={r.eta_seconds} />
        </div>
      ))}

      {result && <p className="text-xs text-muted-foreground">{result}</p>}
    </div>
  );
}
