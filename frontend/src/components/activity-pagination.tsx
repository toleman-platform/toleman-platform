"use client";

import { useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";

/**
 * Shared "activity feed" pagination footer (issue #123) — same
 * Previous/Next + "Showing X-Y of Z" shape as findings-list.tsx's footer,
 * extracted so Audit Log and GitHub Org Logs (both real-paginated for the
 * first time here) render it identically instead of two hand-rolled copies.
 */
export function ActivityPagination({ total, page, pageSize }: { total: number; page: number; pageSize: number }) {
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

  if (total === 0) return null;

  return (
    <div className="flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
      <span>
        Showing {rangeStart}-{rangeEnd} of {total}
      </span>
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
