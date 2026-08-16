"use client";

import { useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { PAGE_SIZE_OPTIONS, DEFAULT_PAGE_SIZE, pageSizeFromParams } from "@/lib/pagination";

/**
 * Shared "activity feed" pagination footer (issue #123) — same
 * Previous/Next + "Showing X-Y of Z" shape as findings-list.tsx's footer,
 * extracted so Audit Log and GitHub Org Logs (both real-paginated for the
 * first time here) render it identically instead of two hand-rolled copies.
 */
// Re-exported for client importers. Server Components must import these from
// "@/lib/pagination" directly -- see that module for why pulling them out of
// this ("use client") file breaks a server-side call.
export { PAGE_SIZE_OPTIONS, DEFAULT_PAGE_SIZE, pageSizeFromParams };

export function ActivityPagination({
  total,
  page,
  pageSize,
  position = "bottom",
}: {
  total: number;
  page: number;
  pageSize: number;
  // A pager only at the foot of the list is invisible until you have already
  // scrolled past everything: /findings renders 25 rows over ~3700px, so a
  // reader hits four screens of cards before discovering the list is paged at
  // all -- which is exactly why it reads as an infinite scroll. Rendering the
  // same control at the top states the size of the result set up front.
  position?: "top" | "bottom";
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("page", String(nextPage));
    router.push(`${pathname}?${params.toString()}`);
  }

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / pageSize)), [total, pageSize]);
  const rangeStart = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const rangeEnd = Math.min(page * pageSize, total);

  function setPageSize(next: number) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("page_size", String(next));
    // Reset to page 1: staying on page 7 while growing the page size can
    // land past the end of the result set, which reads as an empty list.
    params.set("page", "1");
    router.push(`${pathname}?${params.toString()}`);
  }

  if (total === 0) return null;

  // The top pager renders whenever the result set could exceed the smallest
  // page size -- not only when it exceeds the *current* one. Gating on the
  // current size stranded the user: pick 100 on a 35-row list, the pager
  // (and with it the size selector) disappears, and there is no way back to
  // 25 short of editing the URL.
  if (position === "top" && total <= PAGE_SIZE_OPTIONS[0]) return null;

  return (
    <div
      className={
        position === "top"
          ? "flex items-center justify-between border-b border-border pb-3 text-xs text-muted-foreground"
          : "flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground"
      }
    >
      <div className="flex items-center gap-3">
        <span>
          Showing {rangeStart}-{rangeEnd} of {total}
        </span>
        {/* Page size is a real preference: triaging wants 100 on screen,
            skimming wants 25. Only rendered on the top pager so the control
            appears once per list rather than twice. */}
        {position === "top" && (
          <label className="flex items-center gap-1.5">
            <span className="sr-only">Rows per page</span>
            <select
              aria-label="Rows per page"
              className="h-6 rounded-md border border-input bg-secondary px-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
            >
              {PAGE_SIZE_OPTIONS.map((n) => (
                <option key={n} value={n}>
                  {n} / page
                </option>
              ))}
            </select>
          </label>
        )}
      </div>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" className="h-7 text-xs" disabled={page <= 1} onClick={() => goToPage(page - 1)}>
          Previous
        </Button>
        <span>
          Page {page} of {totalPages}
        </span>
        <Button
          size="sm"
          variant="outline"
          className="h-7 text-xs"
          disabled={page >= totalPages}
          onClick={() => goToPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
