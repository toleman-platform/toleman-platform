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
import type { FindingFilterOptions, FindingGroupSort } from "@/types";

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
  // (#251) The owning target's metadata, multi-select since #270 like every
  // other filter in the bar.
  const environment = toArray(sp.environment);
  const owner = toArray(sp.owner);
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
    environment,
    owner,
    target_id,
    group_id,
    search,
    new_since_days,
    exclude_category: queued.exclude_category,
  };

  const listQuery = { ...commonFilters, category, state, resolved: queued.resolved };

  const [groupsResult, findingsResult, targets, facets, groups, queueCounts] = await Promise.all([
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
    // (#270) Every dimension's per-value counts in one call, taking exactly
    // the filters the list above took. Each dimension is counted with every
    // OTHER filter applied but not its own, so the filter bar reads as a
    // summary of this view of the backlog; the `category` dimension it
    // returns is what the category tabs below are counted from, so tabs and
    // pills can't tell different stories about the same query. `null` when
    // it fails; see the fallback below.
    api.findingFacets(listQuery).catch(() => null),
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

  // Only when the one facets call failed: a second, serialized round of the
  // plain per-dimension endpoints. Tool, Environment and Owner have no
  // hardcoded option set -- theirs come from real data -- so without this a
  // single failure removes three controls and the category tabs outright,
  // and an active ?tool=semgrep becomes something you can see the effects
  // of but not switch off. Costs an extra round-trip on the failure path
  // and nothing at all on the normal one.
  const fallbackOptions: FindingFilterOptions | null = facets
    ? null
    : await (async () => {
        const [toolOptions, environmentOptions, ownerOptions, categoryCounts] = await Promise.all([
          api.findingTools().catch(() => []),
          api.findingEnvironments().catch(() => []),
          api.findingOwners().catch(() => []),
          // This one still carries real counts, so the category tabs keep
          // their numbers even on the degraded path. Only the "All findings"
          // queue shows them; the other three already pin the category.
          queue === "all"
            ? api.findingCategories({ ...commonFilters, state, resolved: queued.resolved }).catch(() => [])
            : Promise.resolve([]),
        ]);
        return {
          tool: toolOptions,
          environment: environmentOptions,
          owner: ownerOptions,
          category: categoryCounts,
        };
      })();

  function hrefWith(overrides: Record<string, string | undefined>): string {
    const params = new URLSearchParams();
    severity.forEach((s) => params.append("severity", s));
    tool.forEach((t) => params.append("tool", t));
    fixability.forEach((f) => params.append("fixability", f));
    environment.forEach((e) => params.append("environment", e));
    owner.forEach((o) => params.append("owner", o));
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

  // Counted from the same /facets call the filter bar renders (its
  // `category` dimension), not a second round-trip: the tabs and the pills
  // are two views of one query, so they read from one answer. On the
  // degraded path they come from /facets/categories instead, which still
  // counts -- so the tabs keep their numbers even when the pills lose
  // theirs.
  const categoryFacets: { value: string; count: number }[] = facets
    ? facets.category
    : (fallbackOptions?.category ?? []).map((c) => ({ value: c.category, count: c.count }));
  const countedCategories = facets !== null || (fallbackOptions?.category.length ?? 0) > 0;
  const categoryTabs: CategoryTab[] = [
    {
      id: "",
      label: "All",
      // null, not 0, when nothing could be counted: an "All 0" tab above a
      // list of findings is a plain contradiction.
      count: countedCategories ? categoryFacets.reduce((sum, c) => sum + c.count, 0) : null,
      href: hrefWith({ category: undefined }),
    },
    ...categoryFacets.map((c): CategoryTab => ({ id: c.value, label: c.value, count: c.count, href: hrefWith({ category: c.value }) })),
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
        groups={groups}
        facets={facets}
        fallbackOptions={fallbackOptions}
        resolved={queued.resolved}
        grouped={grouped}
        // The flat view has no blast-radius ordering, so handing it that value
        // left the select matching none of its options and rendering blank.
        // Switching grouped -> flat with `sort=blast_radius` in the URL did
        // exactly that.
        sort={!grouped && sort === "blast_radius" ? "exploitability" : sort}
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
          truncated={groupsResult.truncated}
          page={page}
          pageSize={pageSize}
          // The same filters the groups were counted under. A row's member
          // list is what group triage acts on, so it has to be drawn from the
          // identical filter set or the row's count and its action disagree.
          memberQuery={listQuery}
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
