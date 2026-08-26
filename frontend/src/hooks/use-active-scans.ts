"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ActiveScans } from "@/lib/api";

/**
 * Which scans are running right now, across every repo the user can see
 * (issue #212).
 *
 * This is the piece that makes a scan visible somewhere other than the page
 * that started it. A scan triggered from Scans used to leave the Targets
 * list showing "last scanned 3 days ago", with nothing to suggest one was in
 * flight; anything that renders a repo can now ask this instead.
 *
 * The interval is adaptive rather than fixed. While something is running the
 * poll is frequent enough that a scan finishing feels immediate; while
 * nothing is running it backs off hard, because the only thing it is
 * watching for then is a scan someone else started, and paying a request
 * every few seconds for that on an idle dashboard is not worth it.
 */
const ACTIVE_INTERVAL_MS = 3000;
const IDLE_INTERVAL_MS = 20000;

export type UseActiveScansResult = {
  activeScans: ActiveScans;
  /** Convenience for the common "is this repo busy?" question. */
  isTargetScanning: (targetId: number) => boolean;
  /** Poll immediately, call right after dispatching so the row flips to
   * running without waiting out the interval. */
  refresh: () => void;
};

export function useActiveScans(): UseActiveScansResult {
  const [activeScans, setActiveScans] = useState<ActiveScans>({});

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef = useRef(false);
  // Read by the scheduler to pick the next delay. A ref rather than state so
  // the loop below does not have to be re-created whenever the data changes,
  // which would stack timers.
  const anyActiveRef = useRef(false);
  // The loop is self-scheduling, so it is held in a ref: a plain function
  // referring to itself before its own declaration is a use-before-declare
  // that the lint rules reject, and rightly so.
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
    // Assume something was just dispatched, so the next polls run at the
    // active cadence rather than the idle one.
    anyActiveRef.current = true;
    loopRef.current();
  }, []);

  const isTargetScanning = useCallback(
    (targetId: number) => (activeScans[String(targetId)]?.length ?? 0) > 0,
    [activeScans],
  );

  return { activeScans, isTargetScanning, refresh };
}
