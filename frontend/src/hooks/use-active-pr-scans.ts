"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ActivePrScans } from "@/lib/api";

/**
 * Which PR Guardrail scans are running right now (finding CTX-02).
 *
 * PrScanAction used to hold "am I scanning" in a local `useState`. Navigating
 * away unmounted the component, so coming back showed a fresh, clickable
 * "Scan This PR" while the scan was still running, and the audit-log card
 * lower on the same page correctly showed `running`. The obvious next user
 * action was to click again and start a duplicate clone-and-scan.
 *
 * Deliberately the same shape as useActiveScans (#212): the server is the
 * source of truth for what is in flight, so a component can render running
 * state without having been the one that started it. Same adaptive interval,
 * for the same reason; responsive while something is running, backed off
 * hard while nothing is, since the only thing it watches for then is a scan
 * someone else started.
 */
const ACTIVE_INTERVAL_MS = 3000;
const IDLE_INTERVAL_MS = 20000;

export type UseActivePrScansResult = {
  activePrScans: ActivePrScans;
  /** Is a guardrail scan running for this exact PR right now? */
  isPrScanning: (targetId: number, prNumber: number) => boolean;
  /** Poll immediately, call right after dispatching so the button flips to
   * running without waiting out the interval. */
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
        // A failed poll is not worth an error banner: the next one is
        // seconds away, and the page has real content that should not be
        // disturbed by a blip in a background refresh.
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
