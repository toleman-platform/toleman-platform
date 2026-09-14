/**
 * Standard Library Asynchronous & Promise Utilities
 */

import type { Nullable } from "./types";

/**
 * Returns a promise that resolves after the specified number of milliseconds.
 *
 * @param ms Delay duration in milliseconds
 * @returns A promise that resolves when the delay completes
 *
 * @example
 * ```ts
 * await sleep(500); // pause execution for 500ms
 * ```
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resolves a promise to its value, or `null` if the promise rejects.
 * Especially useful in Server Components and async data loaders to distinguish
 * errors from empty states without triggering React state mutation rules.
 *
 * @param promise The promise to safely settle
 * @returns The resolved value, or null if rejected
 *
 * @example
 * ```ts
 * const user = await settleOrNull(fetchUserProfile());
 * ```
 */
export async function settleOrNull<T>(promise: Promise<T>): Promise<Nullable<T>> {
  try {
    return await promise;
  } catch {
    return null;
  }
}

/**
 * The value a settled promise produced, paired with whether it had to fall
 * back. `true` means the request failed and `value` is the caller's fallback.
 */
export type Settled<T> = readonly [value: T, failed: boolean];

/**
 * Resolve a promise to its value, or to `fallback` **plus the fact that it
 * fell back**.
 *
 * This exists because of a bug class that kept recurring across the four
 * operator surfaces. `settleOrNull` produces exactly the bit that separates
 * "the API answered with nothing" from "the API did not answer" — and then
 * every call site threw that bit away one line later:
 *
 * ```ts
 * const summary = (await settleOrNull(api.scanSummary())) ?? {};  // bit lost
 * ```
 *
 * With the boolean gone, downstream code reads the empty map and renders a
 * confident factual claim: every target "never scanned", every count `0`,
 * a green zero on a repository that may have hundreds of open findings.
 * `AGENTS.md` §1.4 and `DESIGN_SYSTEM.md` §18 both forbid precisely that, and
 * the rule the whole design system rests on is that **a failed, skipped or
 * unknown check must never render as clean**.
 *
 * So the convention is: a *secondary* fetch may degrade the page rather than
 * failing it, but the page has to keep the boolean and render the
 * degradation — see `PartialFailureBanner` for the shared way to say it, and
 * `DESIGN_SYSTEM.md` §20's partial-failure rule for why the successfully
 * loaded half must still be shown.
 *
 * Use `settleOrNull` when `null` is a usable sentinel on its own (a single
 * object the page either has or does not have); use `settledOr` when the
 * fallback is an empty collection, because an empty collection is
 * indistinguishable from a real result and is where the misinformation gets in.
 *
 * @param promise The promise to safely settle
 * @param fallback The value to use if the promise rejects
 * @returns `[value, failed]`
 *
 * @example
 * ```ts
 * const [summary, summaryFailed] = await settledOr(api.scanSummary(), {});
 * // render `summaryFailed` — never let it decay back into `{}`
 * ```
 */
export async function settledOr<T>(promise: Promise<T>, fallback: T): Promise<Settled<T>> {
  try {
    return [await promise, false] as const;
  } catch {
    return [fallback, true] as const;
  }
}
