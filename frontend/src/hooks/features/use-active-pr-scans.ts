"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ActivePrScans } from "@/lib/api";

/**
 * L3 Domain Hook: Monitors running PR Guardrail scans in real time (finding CTX-02).
 *
 * Uses the server as the single source of truth for in-flight PR Guardrail scans,
 * preventing duplicate scan triggers when users navigate away and return.
 * Employs adaptive polling: 3s while scans run, 20s while idle.
 */
const ACTIVE_INTERVAL_MS = 3000;
const IDLE_INTERVAL_MS = 20000;

export type UseActivePrScansResult = {
  activePrScans: ActivePrScans;
  /** Checks whether a PR Guardrail scan is currently executing for a target and PR */
  isPrScanning: (targetId: number, prNumber: number) => boolean;
  /** Immediately forces an active-cadence poll */
  refresh: () => void;
};

export function useActivePrScans(): UseActivePrScansResult {
  const [activePrScans, setActivePrScans] = useState<ActivePrScans>({});

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef = useRef(false);
  const anyActiveRef = useRef(false);
  const loopRef = useRef<() => void>(() => {});

  useEffect(() => {
    stoppedRef.current = false;

    async function pollOnce() {
      try {
        const data = await api.activePrScans();
        if (stoppedRef.current) return;
        setActivePrScans(data);
        anyActiveRef.current = Object.keys(data).length > 0;
      } catch {
        // Suppress background poll errors
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

  const isPrScanning = useCallback(
    (targetId: number, prNumber: number) => Boolean(activePrScans[`${targetId}:${prNumber}`]),
    [activePrScans],
  );

  return { activePrScans, isPrScanning, refresh };
}
