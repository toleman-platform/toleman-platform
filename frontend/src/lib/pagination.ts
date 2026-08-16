/**
 * Pagination constants shared by Server Components and the client-side
 * ActivityPagination control.
 *
 * These live in a plain (non-"use client") module for the same reason
 * @/lib/theme does: a Server Component importing a value from a client
 * module does not get the value. For a constant it silently becomes a client
 * reference stub; for a *function* Next fails loudly with "Attempted to call
 * pageSizeFromParams() from the server but pageSizeFromParams is on the
 * client". This module was created after hitting exactly that, having
 * originally exported these from components/activity-pagination.tsx.
 */
export const PAGE_SIZE_OPTIONS = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 25;

/** Reads the page-size preference off the URL, clamped to the allowed set so
 * a hand-edited `?page_size=100000` cannot ask the server for everything. */
export function pageSizeFromParams(raw: string | string[] | undefined): number {
  const value = Number(Array.isArray(raw) ? raw[0] : raw);
  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(value) ? value : DEFAULT_PAGE_SIZE;
}
