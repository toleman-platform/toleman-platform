/**
 * Resolve a promise to its value, or `null` on rejection; used in async
 * server components to distinguish "the API call failed" (render an
 * ErrorState with a retry action) from "the API call succeeded with an
 * empty result" (render an EmptyState), without the
 * `let failed = false; promise.catch(() => { failed = true; ... })`
 * pattern, which the project's `react-hooks/immutability` lint rule flags
 * as reassigning a variable after render starts.
 */
export async function settleOrNull<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch {
    return null;
  }
}
