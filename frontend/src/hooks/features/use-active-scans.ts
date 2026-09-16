"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ActiveScans } from "@/lib/api";
import { useWorkspaceContext } from "@/contexts/workspace-context";

/**
 * L3 Domain Hook: Monitors running scans across all target repositories (issue #212).
 *
 * Provides shared in-flight scanning visibility across disparate dashboard surfaces.
 * Uses an adaptive polling cadence:
 * - 3,000ms while any scan is running for responsive progress transitions.
 * - 20,000ms while idle to eliminate unnecessary background request load.
 */
const ACTIVE_INTERVAL_MS = 3000;
const IDLE_INTERVAL_MS = 20000;

export type UseActiveScansResult = {
  activeScans: ActiveScans;
  /** Convenience predicate checking if a specific target repo has scans in flight */
  isTargetScanning: (targetId: number) => boolean;
  /** Immediately forces an active-cadence poll (e.g. right after dispatching a new scan) */
  refresh: () => void;
};

export function useActiveScans(): UseActiveScansResult {
  const [activeScans, setActiveScans] = useState<ActiveScans>({});
  // (#506) Follows the global workspace switcher, same as every other
  // dashboard surface; "All workspaces" (null) preserves the previous
  // unfiltered/accessible-scope behavior.
  const { activeWorkspaceId } = useWorkspaceContext();

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const anyActiveRef = useRef(false);
  const loopRef = useRef<() => void>(() => {});

  useEffect(() => {
    // Effect-local, not a ref: a ref shared across effect re-runs is
    // exactly the bug this replaced. Switching the active workspace tears
    // down this effect and mounts a new one in the same commit; the old
    // cleanup set a *shared* stoppedRef to true, and the new effect's own
    // body immediately reset that same ref back to false -- so a poll
    // in flight for the *previous* workspace, if it resolved after the
    // switch, saw `stoppedRef.current === false` (the new effect's doing)
    // and applied the old workspace's scan data over the new one's. Each
    // effect instance now closes over its own `cancelled`, so a stale
    // instance's in-flight request can only ever see its own flag.
    let cancelled = false;

    async function pollOnce() {
      try {
        const data = await api.activeScans(activeWorkspaceId);
        if (cancelled) return;
        setActiveScans(data);
        anyActiveRef.current = Object.keys(data).length > 0;
      } catch {
        // Suppress transient poll blips from disrupting foreground UI
      }
    }

    function schedule() {
      if (cancelled) return;
      const delay = anyActiveRef.current ? ACTIVE_INTERVAL_MS : IDLE_INTERVAL_MS;
      timerRef.current = setTimeout(() => {
        void pollOnce().then(schedule);
      }, delay);
    }

    loopRef.current = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      void pollOnce().then(schedule);
    };

    loopRef.current();

    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [activeWorkspaceId]);

  const refresh = useCallback(() => {
    anyActiveRef.current = true;
    loopRef.current();
  }, []);

  const isTargetScanning = useCallback(
    (targetId: number) => (activeScans[String(targetId)]?.length ?? 0) > 0,
    [activeScans],
  );

  return { activeScans, isTargetScanning, refresh };
}
