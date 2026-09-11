import { api } from "@/lib/api";
import { FindingsFilterBar } from "@/components/findings-filter-bar";
import { FindingsCategoryTabs, type CategoryTab } from "@/components/findings-category-tabs";
import { FindingsList } from "@/components/findings-list";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";
// Plain module, not the "use client" component; a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";

// Page size is now a user preference read off the URL (25/50/100),
// defaulting to 25. See components/activity-pagination.tsx.

function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

// severity/tool/fixability/state/target_id are all multi-select in the
// filter bar (repeated query params, e.g. `?severity=Critical&severity=
// High`); Next.js already hands back a string[] for a repeated key, a
// bare string for exactly one, so this just always normalizes to an array.
function toArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const severity = toArray(sp.severity);
  const tool = toArray(sp.tool);
  const category = firstValue(sp.category);
  const fixability = toArray(sp.fixability);
  const state = toArray(sp.state);
  const search = firstValue(sp.search);
  const targetIdRaw = toArray(sp.target_id);
  const target_id = targetIdRaw.map(Number);
  const groupIdRaw = firstValue(sp.group_id);
  const group_id = groupIdRaw ? Number(groupIdRaw) : undefined;
  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSizeRaw = firstValue(sp.page_size);
  const pageSize = pageSizeFromParams(sp.page_size);
  // Count only open issues by default (issue: fixed/resolved findings were
  // inflating category tab counts); an explicit `?resolved=true` switches
  // to the Resolved view. "Open" here means Open+Reopened, same split
  // OPEN_FINDING_STATES/RESOLVED_FINDING_STATES already use server-side.
  const resolved = firstValue(sp.resolved) === "true";

  const commonFilters = { severity, tool, fixability, target_id, group_id, search };

  const [findingsResult, targets, tools, categoryFacets, groups, openTotal, resolvedTotal] = await Promise.all([
    settleOrNull(api.findings({ ...commonFilters, category, state, resolved, page, page_size: pageSize })),
    api.targets().catch(() => []),
    api.findingTools().catch(() => []),
    // Filter-aware (severity/tool/state/search/target/group/fixability/
    // resolved, but deliberately not category itself -- see
    // list_category_facets): each tab's count reflects every OTHER active
    // filter and the active Open/Resolved view, the way a real facet count
    // should.
    api.findingCategories({ ...commonFilters, state, resolved }).catch(() => []),
    api.groups().catch(() => []),
    // Open/Resolved tab counts: same filters as the category tabs (severity
    // /tool/fixability/target/group/search/category), but never `state` --
    // the State filter's own options differ per view (OPEN_STATES vs
    // RESOLVED_STATES in findings-filter-bar.tsx), so switching views drops
    // it, and these counts reflect what that switch actually shows.
    api.findings({ ...commonFilters, category, resolved: false, page_size: 1 }).then((r) => r.total).catch(() => 0),
    api.findings({ ...commonFilters, category, resolved: true, page_size: 1 }).then((r) => r.total).catch(() => 0),
  ]);
  const result = findingsResult ?? { items: [], total: 0 };

  // Both the Open/Resolved split and category are navigation (tabs), not
  // filter dropdowns: each tab is a real link that preserves every other
  // active filter, same "tab state in the URL" convention as
  // targets/[id]/target-tabs.tsx and the Approval Queue's Requests/History
  // split.
  function baseParams(): URLSearchParams {
    const params = new URLSearchParams();
    severity.forEach((s) => params.append("severity", s));
    tool.forEach((t) => params.append("tool", t));
    fixability.forEach((f) => params.append("fixability", f));
    targetIdRaw.forEach((t) => params.append("target_id", t));
    if (group_id) params.set("group_id", String(group_id));
    if (search) params.set("search", search);
    if (pageSizeRaw) params.set("page_size", pageSizeRaw);
    return params;
  }

  function categoryHref(nextCategory?: string): string {
    const params = baseParams();
    state.forEach((s) => params.append("state", s));
    params.set("resolved", String(resolved));
    if (nextCategory) params.set("category", nextCategory);
    const qs = params.toString();
    return qs ? `/findings?${qs}` : "/findings";
  }

  function resolvedHref(nextResolved: boolean): string {
    const params = baseParams();
    if (category) params.set("category", category);
    params.set("resolved", String(nextResolved));
    // `state` intentionally dropped: Open and Resolved offer different
    // state options, so a state picked in one view doesn't carry into
    // the other.
    const qs = params.toString();
    return qs ? `/findings?${qs}` : "/findings";
  }

  const resolvedTabs: CategoryTab[] = [
    { id: "open", label: "Open", count: openTotal, href: resolvedHref(false) },
    { id: "resolved", label: "Resolved", count: resolvedTotal, href: resolvedHref(true) },
  ];
  const categoryTabs: CategoryTab[] = [
    { id: "", label: "All", count: categoryFacets.reduce((sum, c) => sum + c.count, 0), href: categoryHref() },
    ...categoryFacets.map((c): CategoryTab => ({ id: c.category, label: c.category, count: c.count, href: categoryHref(c.category) })),
  ];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">All Findings</h1>
        <p className="text-sm text-muted-foreground">{result.total} findings across all targets</p>
      </div>
      <FindingsCategoryTabs tabs={resolvedTabs} active={resolved ? "resolved" : "open"} />
      <FindingsCategoryTabs tabs={categoryTabs} active={category ?? ""} />
      <FindingsFilterBar targets={targets} tools={tools} groups={groups} resolved={resolved} />
      {findingsResult === null ? (
        <ErrorState
          description="The findings list couldn't be loaded from the API."
          action={<ReloadButton />}
        />
      ) : (
        <FindingsList findings={result.items} total={result.total} page={page} pageSize={pageSize} targets={targets} />
      )}
    </div>
  );
}
