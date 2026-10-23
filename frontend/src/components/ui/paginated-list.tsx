"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { ListRows } from "@/components/ui/list-row";
import { ActivityPagination } from "@/components/ui/activity-pagination";

/**
 * Shared list shell: count, page size, top/bottom pagination, density spacing, and
 * empty state. Let ActivityPagination decide visibility so page-size controls remain
 * reachable. Callers own rows, selection, bulk actions, and toolbars; controls needed
 * with zero selection must stay outside BulkActionBar. Render only after a successful
 * read: total=0 must be a measured result.
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
