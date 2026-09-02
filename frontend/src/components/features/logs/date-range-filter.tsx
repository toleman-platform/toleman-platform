"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Input } from "@/components/ui/input";

/**
 * Shared "activity feed" date-range filter (issue #123), the one filter
 * common to both Audit Log and GitHub Org Logs. Reads/writes date_from and
 * date_to query params directly (no local state to reconcile), same
 * URL-is-the-source-of-truth approach as FindingsFilterBar's dropdowns.
 */
export function DateRangeFilter() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  function updateParam(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  return (
    <div className="flex items-center gap-1.5">
      <Input
        type="date"
        aria-label="From date"
        className="h-8 w-[9.5rem] bg-secondary text-xs"
        value={searchParams.get("date_from") ?? ""}
        onChange={(e) => updateParam("date_from", e.target.value)}
      />
      <span className="text-xs text-muted-foreground">to</span>
      <Input
        type="date"
        aria-label="To date"
        className="h-8 w-[9.5rem] bg-secondary text-xs"
        value={searchParams.get("date_to") ?? ""}
        onChange={(e) => updateParam("date_to", e.target.value)}
      />
    </div>
  );
}
