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
