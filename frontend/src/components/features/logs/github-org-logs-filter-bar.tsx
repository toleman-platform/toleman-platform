"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Target } from "@/lib/api";
import { TargetPicker, ALL_TARGETS } from "@/components/features/targets";
import { DateRangeFilter } from "./date-range-filter";

export function GithubOrgLogsFilterBar({ targets }: { targets: Target[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const targetIds = searchParams.getAll("target_id").map(Number);
  // No target_id params in the URL reads as "All repositories" -- represent
  // that in TargetPicker's own terms rather than inventing a second "empty
  // means all" convention on top of its ALL_TARGETS sentinel.
  const pickerValue = targetIds.length > 0 ? targetIds : [ALL_TARGETS];

  function setTargetIds(ids: number[]) {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("target_id");
    if (!ids.includes(ALL_TARGETS)) {
      for (const id of ids) params.append("target_id", String(id));
    }
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  const hasFilters = targetIds.length > 0 || ["date_from", "date_to"].some((k) => searchParams.get(k));

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <TargetPicker targets={targets} value={pickerValue} onChange={setTargetIds} allowAll label="Filter by repository" />

      <DateRangeFilter />

      {hasFilters && (
        <button onClick={() => router.push(pathname)} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
