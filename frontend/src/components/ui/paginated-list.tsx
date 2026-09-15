"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { ListRows } from "@/components/ui/list-row";
import { ActivityPagination } from "@/components/activity-pagination";

/**
 * The shell every scannable list in this app rebuilds around `ListRow`.
 *
 * `ListRow` solved one row. The layer above it -- count line, page-size
 * control, top pager, density-aware stack, empty state, foot pager -- was
 * still copied per surface, and the copies had drifted:
 *
 *   - findings-list.tsx gates its top pager on `total > pageSize`. At
 *     `?page_size=100` on a 40-row result that is false, so the pager (and
 *     with it the only control that gets you back to 25 rows) disappears --
 *     the exact trap ActivityPagination documents and guards against
 *     internally. Gating here is therefore left to ActivityPagination alone.
 *   - the SBOM components list rendered the top pager and no foot pager, so
 *     paging a 717-component inventory meant scrolling back up every time.
 *   - it also stacked rows with a fixed `gap-2` rather than
 *     `--density-list-gap`, so Compact did nothing to the space between rows.
 *
 * What this component deliberately does NOT own: the row itself
 * (`renderItem`), selection, bulk actions and filter bars (`toolbar`), and
 * anything that has to survive an empty selection -- `BulkActionBar` returns
 * null at `count === 0`, so a control that must stay reachable with nothing
 * selected cannot be nested inside it.
 *
 * Honesty rule (AGENTS.md 1.4): `total` is a measurement. Render this
 * component only once the result set has actually been read back. A failed or
 * not-yet-run request passed through as `total={0}` renders a confident
 * "0 components", which is a different claim from "we have not looked".
 */
export type PaginatedListProps<T> = {
  /** The rows on the page currently displayed, not the whole result set. */
  items: T[];
  /** Size of the whole result set across every page; drives the count and pager. */
  total: number;
  page: number;
  pageSize: number;
  /** Stable identity per row. Index keys silently relabel rows on reorder. */
  getKey: (item: T, index: number) => React.Key;
  renderItem: (item: T, index: number) => React.ReactNode;
  /**
   * Singular noun for the count line, e.g. "component" -> "717 components".
   * Omit both this and `summary` to render no count line at all.
   */
  itemNoun?: string;
  /** Irregular plural; defaults to `itemNoun + "s"`. */
  itemNounPlural?: string;
  /** Replaces the generated count line outright, for lists that count two
   * things at once ("12 decisions across 87 findings"). `null` removes it. */
  summary?: React.ReactNode;
  /** Rendered between the count line and the pager: select-all, filters,
   * search, bulk bars, truncation warnings. */
  toolbar?: React.ReactNode;
  /** Shown in place of the rows when this page has none. Rendered inside the
   * list rather than replacing it, so overshooting the last page still leaves
   * the pager that gets you back. */
  empty?: React.ReactNode;
  /** Wraps the rows in something other than the default density-aware stack --
   * the grouped findings list needs a `role="table"` with a header row. */
  renderRows?: (rows: React.ReactNode) => React.ReactNode;
  className?: string;
};

export function PaginatedList<T>({
  items,
  total,
  page,
  pageSize,
  getKey,
  renderItem,
  itemNoun,
  itemNounPlural,
  summary,
  toolbar,
  empty,
  renderRows,
  className,
}: PaginatedListProps<T>) {
  // Built as one string rather than JSX with an emphasised <span>: a count
  // split across child elements stops matching a plain text query, and this
  // line is the first thing anyone looks for.
  const generatedSummary =
    itemNoun === undefined
      ? null
      : `${total} ${total === 1 ? itemNoun : (itemNounPlural ?? `${itemNoun}s`)}`;
  const countLine = summary === undefined ? generatedSummary : summary;

  const rows = items.map((item, index) => (
    <React.Fragment key={getKey(item, index)}>{renderItem(item, index)}</React.Fragment>
  ));

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {countLine !== null && <p className="text-xs text-muted-foreground">{countLine}</p>}

      {toolbar}

      <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />

      {items.length === 0 ? empty : renderRows ? renderRows(rows) : <ListRows>{rows}</ListRows>}

      <ActivityPagination total={total} page={page} pageSize={pageSize} />
    </div>
  );
}
