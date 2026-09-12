/**
 * Resolve a promise to its value, or `null` on rejection; used in async
 * server components to distinguish "the API call failed" (render an
 * ErrorState with a retry action) from "the API call succeeded with an
 * empty result" (render an EmptyState).
 */
export { settleOrNull } from "@/std-lib";
