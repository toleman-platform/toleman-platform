"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Group } from "@/lib/api";

// Shared "filter by group" dropdown for the targets list and findings list
// (issue #61), drives a `group_id` search param the same way
// findings-filter-bar.tsx already drives severity/tool/state/target_id, so
// filtering survives navigation/back-forward and can be linked directly.
export function GroupFilter({ groups }: { groups: Group[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  function updateParam(value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set("group_id", value);
    else params.delete("group_id");
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  return (
    <select
      aria-label="Filter by group"
      className="h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
      value={searchParams.get("group_id") ?? ""}
      onChange={(e) => updateParam(e.target.value)}
    >
      <option value="">All groups</option>
      {groups.map((g) => (
        <option key={g.id} value={g.id}>
          {g.name}
        </option>
      ))}
    </select>
  );
}
