"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { ActiveScans } from "@/types";

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

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef = useRef(false);
  const anyActiveRef = useRef(false);
  const loopRef = useRef<() => void>(() => {});

  useEffect(() => {
    stoppedRef.current = false;

    async function pollOnce() {
      try {
        const data = await api.activeScans();
        if (stoppedRef.current) return;
        setActiveScans(data);
        anyActiveRef.current = Object.keys(data).length > 0;
      } catch {
        // Suppress transient poll blips from disrupting foreground UI
      }
    }

    function schedule() {
      if (stoppedRef.current) return;
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
      stoppedRef.current = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

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
