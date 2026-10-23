/** Shared findings URL parsing for the Findings page and target Vulnerabilities tab.
 * Keep this module server-compatible: both callers are Server Components.
 */
import type { FindingGroupSort } from "@/types";
import { pageSizeFromParams } from "@/lib/pagination";

export type SearchParamRecord = Record<string, string | string[] | undefined>;

export function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/** Normalize single and repeated query values for multi-select filters. */
export function toArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

// Keep policy review separate from the incident triage queue.
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

/** Preserve raw URL values alongside parsed filters for lossless link building. */
export function parseFindingsView(sp: SearchParamRecord) {
  const severity = toArray(sp.severity);
  const tool = toArray(sp.tool);
  const fixability = toArray(sp.fixability);
  const state = toArray(sp.state);
  const search = firstValue(sp.search);
  // Match exact rules; free-text search can include unrelated findings.
  const rule_id = toArray(sp.rule_id);
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

  // Default to one row per decision; flat view shows every detection.
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
    rule_id,
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
