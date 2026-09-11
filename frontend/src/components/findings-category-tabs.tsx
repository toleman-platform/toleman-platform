import Link from "next/link";
import { cn } from "@/lib/utils";

// Vulnerability-type navigation for the Findings page (Code/SAST, Secret,
// OSS/SCA, License, IaC, AI/ML, ...), same vocabulary Tool Marketplace
// already shows. Tabs, not a filter dropdown -- each one is a real,
// linkable destination (?category=SCA), same "tab state lives in the URL"
// convention as targets/[id]/target-tabs.tsx and the Approval Queue's own
// Requests/History split, rather than a <select> nobody can send a link to.
//
// A plain Link-based component (no "use client"), so the Findings page
// stays a Server Component: findings/page.tsx computes each tab's href
// (preserving every other active filter) and count (via
// api.findingCategories(), itself filter-aware -- see
// app/api/findings.py::list_category_facets) up front, so this component
// only renders what it's given.
export type CategoryTab = {
  id: string; // "" for the "All" tab
  label: string;
  count: number;
  href: string;
};

export function FindingsCategoryTabs({ tabs, active }: { tabs: CategoryTab[]; active: string }) {
  return (
    <div className="min-w-0 overflow-x-auto border-b border-border">
      <div className="flex w-max min-w-full gap-1">
        {tabs.map((tab) => (
          <Link
            key={tab.id}
            href={tab.href}
            scroll={false}
            aria-current={active === tab.id ? "page" : undefined}
            className={cn(
              "shrink-0 border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              active === tab.id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            <span className="ml-1.5 text-xs text-muted-foreground">{tab.count}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
