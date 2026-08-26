"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ToolInstallRun } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";

/**
 * Drives the marketplace's one-click install (#216).
 *
 * Same dispatch-then-poll shape as useScanRun, and kept separate on purpose:
 * an install has a different vocabulary (a package, a resulting version, a
 * pip output tail) and a different failure story, and collapsing the two
 * into a generic "job" hook would mean neither could name what it is doing.
 *
 * Tracks per tool rather than as a single global, because the marketplace
 * renders a grid and an admin kitting out a fresh deployment will start
 * several installs before the first finishes. A single in-flight slot would
 * make the second click silently discard the first.
 */
export type ToolInstallState = {
  status: "running" | "completed" | "failed";
  version: string;
  error: string;
  output: string;
};

export type UseToolInstallResult = {
  /** Per-tool state, keyed by registry key. */
  installs: Record<string, ToolInstallState>;
  install: (tool: string) => Promise<void>;
  dismiss: (tool: string) => void;
};

const POLL_INTERVAL_MS = 3000;
// Installing a big dependency tree (modelscan pulls tensorflow) is genuinely
// slow, so this is far longer than a scan poll would allow. The backend
// bounds the install itself; this only bounds how long the UI watches.
const POLL_TIMEOUT_MS = 16 * 60 * 1000;

export function useToolInstall(onSettled?: () => void): UseToolInstallResult {
  const [installs, setInstalls] = useState<Record<string, ToolInstallState>>({});
  const cancellersRef = useRef<Record<string, () => void>>({});

  const onSettledRef = useRef(onSettled);
  useEffect(() => {
    onSettledRef.current = onSettled;
  });

  useEffect(
    () => () => {
      for (const cancel of Object.values(cancellersRef.current)) cancel();
      cancellersRef.current = {};
    },
    [],
  );

  const set = useCallback((tool: string, state: ToolInstallState) => {
    setInstalls((prev) => ({ ...prev, [tool]: state }));
  }, []);

  const apply = useCallback(
    (tool: string, run: ToolInstallRun) => {
      set(tool, {
        status: run.status,
        version: run.installed_version,
        // The real reason, not a generic "failed"; "No matching
        // distribution" and "the tool did not report a version when run"
        // call for completely different responses from an admin.
        error: run.error,
        output: run.output_tail,
      });
      if (run.status !== "running") onSettledRef.current?.();
    },
    [set],
  );

  const watch = useCallback(
    (tool: string, runId: number) => {
      cancellersRef.current[tool]?.();
      cancellersRef.current[tool] = pollUntilSettled(
        async () => {
          const run = await api.getToolInstall(runId);
          return { status: run.status, run };
        },
        (result) => apply(tool, result.run),
        {
          intervalMs: POLL_INTERVAL_MS,
          timeoutMs: POLL_TIMEOUT_MS,
          onError: (e) =>
            set(tool, {
              status: "failed",
              version: "",
              error: e instanceof Error ? e.message : "lost contact with the install",
              output: "",
            }),
        },
      );
    },
    [apply, set],
  );

  // (CTX-03) Adopt installs that were already running before this component
  // mounted. Without this, navigating away during an install and coming back
  // showed a fresh "Install" button for a job still running on the worker;
  // the same lost-in-flight-state bug as CTX-02 on PR History, and the same
  // fix: ask the server what is running rather than trusting local state to
  // have survived.
  useEffect(() => {
    let cancelled = false;
    api
      .activeToolInstalls()
      .then((running) => {
        if (cancelled) return;
        for (const [tool, run] of Object.entries(running)) {
          set(tool, { status: "running", version: "", error: "", output: "" });
          watch(tool, run.run_id);
        }
      })
      .catch(() => {
        // A failed adopt is not worth an error banner; the page still
        // works, it just cannot show a pre-existing install until reload.
      });
    return () => {
      cancelled = true;
    };
  }, [set, watch]);

  const install = useCallback(
    async (tool: string) => {
      cancellersRef.current[tool]?.();
      set(tool, { status: "running", version: "", error: "", output: "" });

      let runId: number;
      try {
        const dispatched = await api.installTool(tool);
        runId = dispatched.run_id;
      } catch (e) {
        // A refused dispatch (not admin, rate limited, not installable)
        // never produces a run id, so it is reported here.
        set(tool, {
          status: "failed",
          version: "",
          error: e instanceof Error ? e.message : "install could not be started",
          output: "",
        });
        return;
      }

      watch(tool, runId);
    },
    [set, watch],
  );

  const dismiss = useCallback((tool: string) => {
    cancellersRef.current[tool]?.();
    delete cancellersRef.current[tool];
    setInstalls((prev) => {
      const next = { ...prev };
      delete next[tool];
      return next;
    });
  }, []);

  return { installs, install, dismiss };
}
