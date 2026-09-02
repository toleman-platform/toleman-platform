/**
 * Standard Library Array & Collection Utilities
 */

/**
 * Returns a new array with duplicate values removed, preserving order of first appearance.
 *
 * @param items Array of primitive or reference values
 * @returns Array with unique elements
 *
 * @example
 * ```ts
 * unique([1, 2, 2, 3, 1]); // [1, 2, 3]
 * ```
 */
export function unique<T>(items: readonly T[]): T[] {
  return Array.from(new Set(items));
}

/**
 * Returns a new array containing only the first item encountered for each unique key.
 *
 * @param items Array of elements to deduplicate
 * @param keyFn Selector function returning the deduplication key
 * @returns Array with unique elements by key
 *
 * @example
 * ```ts
 * const users = [{ id: 1, name: "Alice" }, { id: 1, name: "Duplicate" }];
 * uniqueBy(users, (u) => u.id); // [{ id: 1, name: "Alice" }]
 * ```
 */
export function uniqueBy<T, K>(
  items: readonly T[],
  keyFn: (item: T) => K,
): T[] {
  const seen = new Set<K>();
  const result: T[] = [];
  for (const item of items) {
    const key = keyFn(item);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(item);
    }
  }
  return result;
}

export interface PaginatedResult<T> {
  /** The items corresponding to the current clamped page window */
  items: T[];
  /** Page number clamped to [1, totalPages] */
  clampedPage: number;
  /** Total number of pages (at least 1) */
  totalPages: number;
  /** Total number of items before slicing */
  totalItems: number;
}

/**
 * Returns a clamped page slice of an array along with pagination metadata.
 * Clamps the requested page between 1 and totalPages to avoid empty slices.
 *
 * @param items Full collection to slice
 * @param page Requested 1-indexed page number
 * @param pageSize Number of items per page
 * @returns Object containing sliced items, clampedPage, totalPages, and totalItems
 *
 * @example
 * ```ts
 * const { items, clampedPage, totalPages } = paginateSlice(list, 1, 25);
 * ```
 */
export function paginateSlice<T>(
  items: readonly T[],
  page: number,
  pageSize: number,
): PaginatedResult<T> {
  const safePageSize = Math.max(1, pageSize);
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / safePageSize));
  const clampedPage = Math.max(1, Math.min(page, totalPages));
  const start = (clampedPage - 1) * safePageSize;

  return {
    items: items.slice(start, start + safePageSize),
    clampedPage,
    totalPages,
    totalItems,
  };
}
