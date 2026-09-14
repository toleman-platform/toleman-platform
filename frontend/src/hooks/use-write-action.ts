"use client";

import { useCallback, useState } from "react";
import { getErrorMessage } from "@/std-lib";

export type WriteAction = {
  /** True while `run`'s work is in flight. Drive `disabled` from this. */
  submitting: boolean;
  /** The message from the last failed `run`, or `null`. Render it. */
  error: string | null;
  /** Drop a stale message, e.g. when the user edits the form and retries. */
  clearError: () => void;
  /**
   * Run a write. Resolves `true` when `work` completed, `false` when it threw
   * (in which case `error` now holds the message). Never rejects, so a caller
   * that does not care about the outcome still cannot accidentally produce an
   * unhandled rejection.
   */
  run: (work: () => Promise<void>) => Promise<boolean>;
};

/**
 * A write that reports its own failure.
 *
 * Every mutating control in the findings surfaces had independently grown the
 * same shape:
 *
 * ```ts
 * setSubmitting(true);
 * try {
 *   await api.bulkTriage(ids, toState, reason);
 *   // ...success path
 * } finally {
 *   setSubmitting(false);   // <- no catch
 * }
 * ```
 *
 * `finally` without `catch` is the silent-failure idiom: the request rejects,
 * the buttons re-enable, the rows do not change, the selection is not cleared,
 * and **nothing is said**. The user cannot distinguish "the write failed" from
 * "the write succeeded but the list has not refreshed yet" — so the natural
 * recovery is to click again, which on the group row is a single click that
 * can move 148 findings.
 *
 * One file already did this correctly (`finding-detail-drawer.tsx`), which is
 * what makes the other three an oversight rather than a policy. Rather than
 * copy that `try/catch/finally` a fourth, fifth and sixth time, the shape
 * lives here once: `submitting` and `error` come from the same place, so it is
 * no longer possible to wire up the disabled state and forget the failure
 * state. Pair it with an `AlertBanner tone="critical"` — see any of the call
 * sites — per `DESIGN_SYSTEM.md` §20's preference for contextual errors.
 *
 * The success path stays inside `work`, after the `await`, exactly where it
 * already was: if the write throws, none of it runs.
 *
 * @param fallbackMessage Used when the thrown value carries no usable message.
 *   Make it specific to the action ("Triage failed"), not generic — §20 again.
 *
 * @example
 * ```tsx
 * const triage = useWriteAction("Triage failed");
 * // ...
 * await triage.run(async () => {
 *   await api.bulkTriage(ids, toState, reason);
 *   selection.clear();
 *   router.refresh();
 * });
 * // ...
 * {triage.error && (
 *   <AlertBanner tone="critical" title="Triage failed">{triage.error}</AlertBanner>
 * )}
 * ```
 */
export function useWriteAction(fallbackMessage = "Something went wrong"): WriteAction {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => setError(null), []);

  const run = useCallback(
    async (work: () => Promise<void>): Promise<boolean> => {
      setSubmitting(true);
      // Cleared up front rather than left to the caller: a retry that fails a
      // second time with a different message, or succeeds, must not leave the
      // previous attempt's banner on screen contradicting the current state.
      setError(null);
      try {
        await work();
        return true;
      } catch (e) {
        setError(getErrorMessage(e, fallbackMessage));
        return false;
      } finally {
        setSubmitting(false);
      }
    },
    [fallbackMessage],
  );

  return { submitting, error, clearError, run };
}
