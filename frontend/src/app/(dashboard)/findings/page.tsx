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

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const severity = firstValue(sp.severity);
  const tool = firstValue(sp.tool);
  const category = firstValue(sp.category);
  const fixability = firstValue(sp.fixability);
  const state = firstValue(sp.state);
  const search = firstValue(sp.search);
  const targetIdRaw = firstValue(sp.target_id);
  const target_id = targetIdRaw ? Number(targetIdRaw) : undefined;
  const groupIdRaw = firstValue(sp.group_id);
  const group_id = groupIdRaw ? Number(groupIdRaw) : undefined;
  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSizeRaw = firstValue(sp.page_size);
  const pageSize = pageSizeFromParams(sp.page_size);

  const [findingsResult, targets, tools, categoryFacets, groups] = await Promise.all([
    settleOrNull(api.findings({ severity, tool, category, state, search, target_id, group_id, fixability, page, page_size: pageSize })),
    api.targets().catch(() => []),
    api.findingTools().catch(() => []),
    // Filter-aware (severity/tool/state/search/target/group/fixability, but
    // deliberately not category itself -- see list_category_facets): each
    // tab's count reflects every OTHER active filter, the way a real facet
    // count should.
    api.findingCategories({ severity, tool, state, search, target_id, group_id, fixability }).catch(() => []),
    api.groups().catch(() => []),
  ]);
  const result = findingsResult ?? { items: [], total: 0 };

  // Category is navigation (tabs), not a filter dropdown: each tab is a
  // real link that preserves every other active filter, same "tab state in
  // the URL" convention as targets/[id]/target-tabs.tsx and the Approval
  // Queue's Requests/History split.
  function tabHref(category?: string): string {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (tool) params.set("tool", tool);
    if (fixability) params.set("fixability", fixability);
    if (state) params.set("state", state);
    if (search) params.set("search", search);
    if (target_id) params.set("target_id", String(target_id));
    if (group_id) params.set("group_id", String(group_id));
    if (pageSizeRaw) params.set("page_size", pageSizeRaw);
    if (category) params.set("category", category);
    const qs = params.toString();
    return qs ? `/findings?${qs}` : "/findings";
  }
  const categoryTabs: CategoryTab[] = [
    { id: "", label: "All", count: categoryFacets.reduce((sum, c) => sum + c.count, 0), href: tabHref() },
    ...categoryFacets.map((c): CategoryTab => ({ id: c.category, label: c.category, count: c.count, href: tabHref(c.category) })),
  ];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">All Findings</h1>
        <p className="text-sm text-muted-foreground">{result.total} findings across all targets</p>
      </div>
      <FindingsCategoryTabs tabs={categoryTabs} active={category ?? ""} />
      <FindingsFilterBar targets={targets} tools={tools} groups={groups} />
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
