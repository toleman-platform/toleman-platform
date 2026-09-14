import { api } from "@/lib/api";
import {
  FindingsFilterBar,
  FindingsList,
  FindingsGroupsList,
} from "@/components/features/findings";
import { FindingsCategoryTabs, type CategoryTab } from "@/components/findings-category-tabs";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { PageHeader } from "@/components/ui/page-header";
import { settleOrNull } from "@/std-lib";
// Plain module, not the "use client" component; a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";
import type { FindingGroupSort } from "@/types";

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

/**
 * The queues a findings page has to offer, and what each one actually asks of
 * the reader.
 *
 * The old page had a single "All" tab. On this repo's own scan that tab is 150
 * findings of which 148 are licence results, so the one Secrets finding — the
 * only item on the page shaped like an incident — sat on page six behind them.
 * Splitting them is not a filter convenience: a copyleft licence on a
 * transitive build binary is a quarterly policy call, a leaked credential is
 * an incident, and the two do not belong in the same ranked list.
 *
 * `Needs action` excludes licences by category rather than listing the
 * categories it wants, so a newly-integrated scanner's findings land in the
 * triage queue by default instead of silently going nowhere.
 */
const POLICY_CATEGORIES = ["License"];

type QueueId = "action" | "license" | "resolved" | "all";

const QUEUES: { id: QueueId; label: string }[] = [
  { id: "action", label: "Needs action" },
  { id: "license", label: "Licence review" },
  { id: "resolved", label: "Resolved" },
  { id: "all", label: "All findings" },
];

function queueFilters(queue: QueueId): {
  resolved: boolean;
  category?: string;
  exclude_category?: string[];
} {
  if (queue === "license") return { resolved: false, category: "License" };
  if (queue === "resolved") return { resolved: true };
  if (queue === "all") return { resolved: false };
  return { resolved: false, exclude_category: POLICY_CATEGORIES };
}

const GROUP_SORTS: FindingGroupSort[] = ["exploitability", "severity", "blast_radius", "age", "recent"];

function parseQueue(raw: string | undefined): QueueId {
  return QUEUES.some((q) => q.id === raw) ? (raw as QueueId) : "action";
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const severity = toArray(sp.severity);
  const tool = toArray(sp.tool);
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

  const queue = parseQueue(firstValue(sp.queue));
  const queued = queueFilters(queue);
  // Category tabs only mean something inside the "All findings" queue; the
  // other three already pin the category dimension, and showing a second,
  // contradicting control for it is how a filter bar starts lying.
  const category = queue === "all" ? firstValue(sp.category) : queued.category;

  // Grouped is the default view: one row per decision. `?view=flat` is the
  // old one-row-per-detection list, kept because "show me every occurrence"
  // is a real question, just not the one a triage queue opens on.
  const grouped = firstValue(sp.view) !== "flat";

  const sortRaw = firstValue(sp.sort);
  const sort = (GROUP_SORTS as string[]).includes(sortRaw ?? "")
    ? (sortRaw as FindingGroupSort)
    : "exploitability";

  const newSinceRaw = firstValue(sp.new_since_days);
  const new_since_days = newSinceRaw ? Number(newSinceRaw) : undefined;

  const commonFilters = {
    severity,
    tool,
    fixability,
    target_id,
    group_id,
    search,
    new_since_days,
    exclude_category: queued.exclude_category,
  };

  const listQuery = { ...commonFilters, category, state, resolved: queued.resolved };

  const [groupsResult, findingsResult, targets, tools, categoryFacets, groups, queueCounts] = await Promise.all([
    grouped
      ? settleOrNull(api.findingGroups({ ...listQuery, sort, page, page_size: pageSize }))
      : Promise.resolve(null),
    grouped
      ? Promise.resolve(null)
      : settleOrNull(
          api.findings({
            ...listQuery,
            sort: sort === "blast_radius" ? "exploitability" : sort,
            page,
            page_size: pageSize,
          }),
        ),
    api.targets().catch(() => []),
    api.findingTools().catch(() => []),
    // Filter-aware (severity/tool/state/search/target/group/fixability/
    // resolved, but deliberately not category itself -- see
    // list_category_facets): each tab's count reflects every OTHER active
    // filter and the active queue, the way a real facet count should.
    queue === "all"
      ? api.findingCategories({ ...commonFilters, state, resolved: queued.resolved }).catch(() => [])
      : Promise.resolve([]),
    api.groups().catch(() => []),
    // One count per queue, each under the same non-queue filters that are
    // active now, so the tab counts describe what clicking them would show.
    Promise.all(
      QUEUES.map((q) => {
        const qf = queueFilters(q.id);
        return api
          .findings({
            ...commonFilters,
            exclude_category: qf.exclude_category,
            category: qf.category,
            resolved: qf.resolved,
            page_size: 1,
          })
          .then((r) => r.total)
          .catch(() => 0);
      }),
    ),
  ]);

  function hrefWith(overrides: Record<string, string | undefined>): string {
    const params = new URLSearchParams();
    severity.forEach((s) => params.append("severity", s));
    tool.forEach((t) => params.append("tool", t));
    fixability.forEach((f) => params.append("fixability", f));
    targetIdRaw.forEach((t) => params.append("target_id", t));
    if (group_id) params.set("group_id", String(group_id));
    if (search) params.set("search", search);
    if (pageSizeRaw) params.set("page_size", pageSizeRaw);
    if (newSinceRaw) params.set("new_since_days", newSinceRaw);
    if (sortRaw) params.set("sort", sortRaw);
    if (queue !== "action") params.set("queue", queue);
    if (!grouped) params.set("view", "flat");
    if (queue === "all" && category) params.set("category", category);
    state.forEach((s) => params.append("state", s));

    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) params.delete(key);
      else params.set(key, value);
    }
    // Any change of queue, view, category or sort resets paging: page 4 of the
    // old result set is rarely page 4 of the new one, and landing on an empty
    // page reads as "no findings" rather than "wrong page".
    params.delete("page");
    const qs = params.toString();
    return qs ? `/findings?${qs}` : "/findings";
  }

  const queueTabs: CategoryTab[] = QUEUES.map((q, i) => ({
    id: q.id,
    label: q.label,
    count: queueCounts[i] ?? 0,
    href: hrefWith({
      queue: q.id === "action" ? undefined : q.id,
      // State options differ between open and resolved views, so a state
      // picked in one does not carry into the other.
      state: undefined,
      category: undefined,
    }),
  }));

  const categoryTabs: CategoryTab[] = [
    { id: "", label: "All", count: categoryFacets.reduce((sum, c) => sum + c.count, 0), href: hrefWith({ category: undefined }) },
    ...categoryFacets.map((c): CategoryTab => ({ id: c.category, label: c.category, count: c.count, href: hrefWith({ category: c.category }) })),
  ];

  const failed = grouped ? groupsResult === null : findingsResult === null;
  const decisions = groupsResult?.total ?? 0;
  const findingsBehind = groupsResult?.total_findings ?? findingsResult?.total ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Findings"
        description={
          grouped && groupsResult
            ? `${decisions} ${decisions === 1 ? "decision" : "decisions"} across ${findingsBehind} ${findingsBehind === 1 ? "finding" : "findings"}`
            : `${findingsBehind} ${findingsBehind === 1 ? "finding" : "findings"} across all targets`
        }
      />

      <FindingsCategoryTabs tabs={queueTabs} active={queue} />
      {queue === "all" && <FindingsCategoryTabs tabs={categoryTabs} active={category ?? ""} />}

      <FindingsFilterBar
        targets={targets}
        tools={tools}
        groups={groups}
        resolved={queued.resolved}
        grouped={grouped}
        sort={sort}
      />

      {failed ? (
        <ErrorState
          description="The findings list couldn't be loaded from the API."
          action={<ReloadButton />}
        />
      ) : grouped && groupsResult ? (
        <FindingsGroupsList
          groups={groupsResult.items}
          total={groupsResult.total}
          totalFindings={groupsResult.total_findings}
          page={page}
          pageSize={pageSize}
          targets={targets}
        />
      ) : (
        <FindingsList
          findings={findingsResult?.items ?? []}
          total={findingsResult?.total ?? 0}
          page={page}
          pageSize={pageSize}
          targets={targets}
        />
      )}
    </div>
  );
}
