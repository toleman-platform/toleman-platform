"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Target } from "@/lib/api";
import { DateRangeFilter } from "@/components/date-range-filter";

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

export function GithubOrgLogsFilterBar({ targets }: { targets: Target[] }) {
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

  const hasFilters = ["target_id", "date_from", "date_to"].some((k) => searchParams.get(k));

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
      <select
        aria-label="Filter by repository"
        className={SELECT_CLASS}
        value={searchParams.get("target_id") ?? ""}
        onChange={(e) => updateParam("target_id", e.target.value)}
      >
        <option value="">All repositories</option>
        {targets.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>

      <DateRangeFilter />

      {hasFilters && (
        <button onClick={() => router.push(pathname)} className="text-xs text-muted-foreground underline hover:text-foreground">
          Clear filters
        </button>
      )}
    </div>
  );
}
