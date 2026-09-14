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
// (preserving every other active filter) and count up front, so this
// component only renders what it's given. Since #270 the counts come from
// the `category` dimension of api.findingFacets() -- the same response the
// filter pills render, so tabs and pills cannot disagree about one query --
// falling back to api.findingCategories() if that call fails. Both are
// filter-aware; see app/api/findings.py::list_finding_facets.
export type CategoryTab = {
  id: string; // "" for the "All" tab
  label: string;
  /**
   * `null` when the count could not be fetched at all.
   *
   * Nullable rather than defaulting to 0, because 0 is a claim. With the
   * findings API down, every queue count fell to `.catch(() => 0)` and the
   * page rendered `Needs action 0 · Licence review 0 · Resolved 0 ·
   * All findings 0` directly above its own "couldn't be loaded" error box:
   * a careless reader takes away "we're clean", a careful one takes away
   * "the UI contradicts itself". A tab with no number says neither.
   */
  count: number | null;
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
            // JSX strips the newline between the label and the count below, so
            // without this the link's accessible name computes to
            // "Needs action12" / "Licence review148". Same explicit-aria-label
            // fix already used on the dashboard's severity chip links.
            aria-label={tab.count === null ? `${tab.label}, count unavailable` : `${tab.label}, ${tab.count}`}
          >
            {tab.label}
            <span className="ml-1.5 text-xs text-muted-foreground" aria-hidden="true">
              {/* Em dash, the codebase's unknown glyph (DESIGN_SYSTEM.md §18). A bare
                  label would be ambiguous with "this build has no counts at all". */}
              {tab.count === null ? "—" : tab.count}
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}
