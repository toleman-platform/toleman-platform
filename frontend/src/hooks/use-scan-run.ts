"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ScanRun } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import type { ScanPhase } from "@/components/scan-status";

/**
 * Follows one dispatched scan from queued to settled (issue #212).
 *
 * Deliberately not built on useAsyncData. That hook models a single request
 * with a definite end; this models a job whose state is only discoverable by
 * asking repeatedly until it stops changing. Bolting a poll loop onto a
 * one-shot fetch hook would have meant a second, subtly different set of
 * cancellation rules inside it.
 *
 * Three details that make the countdown behave:
 *
 *  1. Elapsed time ticks locally between polls, anchored to the server's
 *     number rather than to the client's clock. Deriving it from
 *     `started_at` against `Date.now()` would fold any client/server clock
 *     skew straight into the display -- a laptop a minute fast would show a
 *     scan as having run for a minute before it was dispatched.
 *  2. The scan starts in `queued`, not `running`. The gap between the API
 *     accepting the dispatch and a worker picking it up is real, and calling
 *     it "running" claims work has begun that may not have.
 *  3. Settling is reported through callbacks fired from the poll, not by
 *     leaving the caller to watch `phase` in an effect. A caller reacting to
 *     a phase change in an effect would fire again on every re-render that
 *     preserved that phase, so it would need its own guard -- and the moment
 *     a scan finishes is a genuine event, not a piece of derived state.
 */
export type UseScanRunOptions = {
  onCompleted?: (findingsCount: number) => void;
  onFailed?: (message: string) => void;
};

export type UseScanRunResult = {
  /** Null when nothing has been dispatched. */
  phase: ScanPhase | null;
  /** Ticks every second while in flight; frozen once settled. */
  elapsedSeconds: number;
  /** Null whenever the server could not ground an estimate in real history. */
  etaSeconds: number | null;
  error: string | null;
  /** Begin following a scan id returned by a dispatch call. */
  track: (scanId: number) => void;
  /** Mark a dispatch as failed before any scan id exists (e.g. a 429). */
  fail: (message: string) => void;
  reset: () => void;
};

const POLL_INTERVAL_MS = 2000;

export function useScanRun({ onCompleted, onFailed }: UseScanRunOptions = {}): UseScanRunResult {
  const [phase, setPhase] = useState<ScanPhase | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [etaSeconds, setEtaSeconds] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  // The server's elapsed count and the local moment it arrived. Elapsed is
  // recomputed from this on each tick, so it advances smoothly between polls
  // without trusting the client clock's absolute value. Held in a ref
  // because it is read inside a timer, not during render -- reading a clock
  // during render is impure and two renders could disagree.
  const anchorRef = useRef<{ serverSeconds: number; at: number } | null>(null);
  const cancelRef = useRef<(() => void) | null>(null);

  // Callbacks are held in refs so a caller passing inline arrows -- which is
  // every caller -- does not re-create `track` on each render.
  const onCompletedRef = useRef(onCompleted);
  const onFailedRef = useRef(onFailed);
  useEffect(() => {
    onCompletedRef.current = onCompleted;
    onFailedRef.current = onFailed;
  });

  const stop = useCallback(() => {
    cancelRef.current?.();
    cancelRef.current = null;
  }, []);

  // Polling must not outlive the component. Without this a user who
  // navigates away mid-scan leaves a request firing every two seconds for
  // the rest of the session.
  useEffect(() => stop, [stop]);

  const inFlight = phase === "queued" || phase === "running";

  useEffect(() => {
    if (!inFlight) return;
    const id = setInterval(() => {
      const anchor = anchorRef.current;
      if (!anchor) return;
      setElapsedSeconds(anchor.serverSeconds + Math.max(0, Math.round((Date.now() - anchor.at) / 1000)));
    }, 1000);
    return () => clearInterval(id);
  }, [inFlight]);

  const apply = useCallback((run: ScanRun) => {
    setPhase(run.status === "running" ? "running" : run.status);
    setEtaSeconds(run.status === "running" ? run.eta_seconds : null);
    setElapsedSeconds(run.elapsed_seconds);
    anchorRef.current = { serverSeconds: run.elapsed_seconds, at: Date.now() };

    if (run.status === "failed") {
      // Prefer the real reason. `mark_stale_if_needed` writes its timeout
      // message into the same field, so a stuck job explains itself here
      // rather than rendering as a spinner that never resolves.
      const message = run.error_message || "Scan failed";
      setError(message);
      onFailedRef.current?.(message);
    } else if (run.status === "completed") {
      onCompletedRef.current?.(run.findings_count);
    }
  }, []);

  const failWith = useCallback((message: string) => {
    setPhase("failed");
    setError(message);
    onFailedRef.current?.(message);
  }, []);

  const track = useCallback(
    (scanId: number) => {
      stop();
      setPhase("queued");
      setError(null);
      setEtaSeconds(null);
      setElapsedSeconds(0);
      anchorRef.current = { serverSeconds: 0, at: Date.now() };

      cancelRef.current = pollUntilSettled(
        async () => {
          const run = await api.getScan(scanId);
          // The API returns { error } for a missing row. Normalising it to a
          // failed status is what stops the loop -- otherwise it would poll
          // a nonexistent scan until the timeout. Same shape as
          // api-discovery's active-scan poll.
          if ("error" in run) {
            return { status: "failed" as const, run: null, message: run.error };
          }
          return { status: run.status, run, message: null };
        },
        (result) => {
          if (result.run) apply(result.run);
          else failWith(result.message ?? "Scan failed");
        },
        {
          intervalMs: POLL_INTERVAL_MS,
          onError: (e) => failWith(e instanceof Error ? e.message : "Lost contact with the scan"),
        },
      );
    },
    [apply, failWith, stop],
  );

  const fail = useCallback(
    (message: string) => {
      stop();
      failWith(message);
    },
    [failWith, stop],
  );

  const reset = useCallback(() => {
    stop();
    setPhase(null);
    setError(null);
    setEtaSeconds(null);
    setElapsedSeconds(0);
    anchorRef.current = null;
  }, [stop]);

  return { phase, elapsedSeconds, etaSeconds, error, track, fail, reset };
}
