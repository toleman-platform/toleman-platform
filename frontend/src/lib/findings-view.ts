/**
 * Shared parsing for every surface that renders a findings list.
 *
 * Two pages show findings: /findings, and a target's Vulnerabilities tab. The
 * tab shipped as a bare paginated list with no filters, no grouping and no
 * sort, so a target with 1,137 findings was a 46-page scroll — the same thing
 * that made /findings unusable before it was grouped.
 *
 * Rather than copy that page's queue, sort and filter parsing into the tab,
 * both read it from here. Duplicating it is how "Needs action" ends up meaning
 * one thing on one page and something slightly different on the other.
 *
 * A plain module, deliberately not a "use client" component: both callers are
 * Server Components, and a Server Component cannot import a value from a
 * client module (see eslint-rules/no-client-value-import-in-server).
 */
import type { FindingGroupSort } from "@/types";
import { pageSizeFromParams } from "@/lib/pagination";

export type SearchParamRecord = Record<string, string | string[] | undefined>;

export function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Next.js hands back a string[] for a repeated query key and a bare string for
 * exactly one. Every multi-select filter normalises to an array so callers
 * never have to care which they got.
 */
export function toArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Categories that are a policy question rather than an incident.
 *
 * A copyleft licence on a transitive build binary is a quarterly call for one
 * person; a leaked credential is an incident. Letting the former set the page
 * count is what buried the latter on page six.
 */
export const POLICY_CATEGORIES = ["License"];

export type QueueId = "action" | "license" | "resolved" | "all";

export const QUEUES: { id: QueueId; label: string }[] = [
  { id: "action", label: "Needs action" },
  { id: "license", label: "Licence review" },
  { id: "resolved", label: "Resolved" },
  { id: "all", label: "All findings" },
];

export function queueFilters(queue: QueueId): {
  resolved: boolean;
  category?: string;
  exclude_category?: string[];
} {
  if (queue === "license") return { resolved: false, category: "License" };
  if (queue === "resolved") return { resolved: true };
  if (queue === "all") return { resolved: false };
  // Excludes by category rather than listing what it wants, so a newly
  // integrated scanner's findings land in triage by default instead of
  // silently going nowhere.
  return { resolved: false, exclude_category: POLICY_CATEGORIES };
}

export function parseQueue(raw: string | undefined): QueueId {
  return QUEUES.some((q) => q.id === raw) ? (raw as QueueId) : "action";
}

export const GROUP_SORTS: FindingGroupSort[] = [
  "exploitability",
  "severity",
  "blast_radius",
  "age",
  "recent",
];

export function parseSort(raw: string | undefined): FindingGroupSort {
  return (GROUP_SORTS as string[]).includes(raw ?? "") ? (raw as FindingGroupSort) : "exploitability";
}

export type FindingsView = ReturnType<typeof parseFindingsView>;

/**
 * Everything both findings surfaces read off the URL.
 *
 * `*Raw` fields are kept alongside the parsed ones because link building has
 * to round-trip exactly what was in the URL: writing back a normalised value
 * would rewrite the reader's address bar on every navigation.
 */
export function parseFindingsView(sp: SearchParamRecord) {
  const severity = toArray(sp.severity);
  const tool = toArray(sp.tool);
  const fixability = toArray(sp.fixability);
  const state = toArray(sp.state);
  const search = firstValue(sp.search);
  // Target metadata filters (#459): filter findings by the owning target's
  // environment or owner. Multi-select, same as severity and tool.
  const environment = toArray(sp.environment);
  const owner = toArray(sp.owner);

  const targetIdRaw = toArray(sp.target_id);
  const groupIdRaw = firstValue(sp.group_id);
  const group_id = groupIdRaw ? Number(groupIdRaw) : undefined;

  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSizeRaw = firstValue(sp.page_size);
  const pageSize = pageSizeFromParams(sp.page_size);

  const queue = parseQueue(firstValue(sp.queue));
  const queued = queueFilters(queue);

  // Grouped is the default: one row per decision. `?view=flat` is the old
  // one-row-per-detection list, kept because "show me every occurrence" is a
  // real question, just not the one a triage queue opens on.
  const grouped = firstValue(sp.view) !== "flat";

  const sortRaw = firstValue(sp.sort);
  const sort = parseSort(sortRaw);

  const newSinceRaw = firstValue(sp.new_since_days);
  // Number("abc") is NaN, which serialises into the query string as the
  // literal "NaN" and earns a 422 from the API — taking the whole page to its
  // error state over a typo in the URL.
  const parsedNewSince = newSinceRaw ? Number(newSinceRaw) : undefined;
  const new_since_days =
    parsedNewSince !== undefined && Number.isFinite(parsedNewSince) ? parsedNewSince : undefined;

  return {
    severity,
    tool,
    fixability,
    state,
    search,
    environment,
    owner,
    targetIdRaw,
    group_id,
    groupIdRaw,
    page,
    pageRaw,
    pageSize,
    pageSizeRaw,
    queue,
    queued,
    grouped,
    sort,
    sortRaw,
    new_since_days,
    newSinceRaw,
  };
}
