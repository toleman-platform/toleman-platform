/**
 * Standard Library Runtime Type Guards
 */

import type { IsDefinedNotNull } from "./types";

/**
 * Type guard predicate asserting that a value is neither `null` nor `undefined`.
 * Narrowing strips both `null` and `undefined`.
 *
 * @param value The value to inspect
 * @returns `true` if `value` is neither `null` nor `undefined`, otherwise `false`
 *
 * @example
 * ```ts
 * const items = ["a", null, "b", undefined];
 * const clean = items.filter(isDefinedNotNull); // string[]
 * ```
 */
export function isDefinedNotNull<T>(value: T): value is IsDefinedNotNull<T> {
  return value !== null && value !== undefined;
}

/**
 * Type guard asserting that an array is non-empty (contains at least one element).
 *
 * @param value The array to inspect
 * @returns `true` if `value` is a valid array with length > 0
 *
 * @example
 * ```ts
 * if (isNonEmptyArray(users)) {
 *   const firstUser = users[0]; // users is narrowed to [User, ...User[]]
 * }
 * ```
 */
export function isNonEmptyArray<T>(
  value: readonly T[] | null | undefined,
): value is [T, ...T[]] {
  return Array.isArray(value) && value.length > 0;
}
