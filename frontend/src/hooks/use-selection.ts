"use client";

import { useCallback, useMemo, useState } from "react";

/**
 * Multi-select state for a paginated list (issue #210).
 *
 * Three lists -- findings, targets, scans -- each hand-rolled the same four
 * primitives: a `Set`, `toggleOne`, `toggleAll` and `allSelected`. They drifted,
 * and the drift caused a real bug: `allSelected` and "select all" were computed
 * against the *filtered* list while the page rendered only a slice of it, so
 * the header checkbox claimed everything was selected when one page was, and
 * "select all" silently selected rows the user could not see. That was fixed
 * per-file in #204; this makes it structural.
 *
 * The rule the API enforces: **`visibleIds` is the page, and select-all acts
 * on the page.** A control the user can see must only ever act on rows the
 * user can see. Bulk-acting on an unseen 1,300 rows because a checkbox was
 * ticked is the kind of thing that ruins someone's afternoon.
 */
export type UseSelectionResult = {
  selected: ReadonlySet<number>;
  selectedIds: number[];
  count: number;
  isSelected: (id: number) => boolean;
  toggle: (id: number, checked: boolean) => void;
  /** Select or clear every id on the current page. */
  toggleAllVisible: (checked: boolean) => void;
  clear: () => void;
  /** Every visible row is selected. False for an empty page -- "all of
   * nothing" should not render as a ticked box. */
  allVisibleSelected: boolean;
  /** Some but not all visible rows are selected. Drives `indeterminate`,
   * which is a DOM property and cannot be set from JSX (see Checkbox). */
  someVisibleSelected: boolean;
};

export function useSelection(visibleIds: readonly number[]): UseSelectionResult {
  const [selected, setSelected] = useState<Set<number>>(() => new Set());

  const toggle = useCallback((id: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }, []);

  const toggleAllVisible = useCallback(
    (checked: boolean) => {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const id of visibleIds) {
          if (checked) next.add(id);
          else next.delete(id);
        }
        return next;
      });
    },
    [visibleIds],
  );

  const clear = useCallback(() => setSelected(new Set()), []);

  const { allVisibleSelected, someVisibleSelected } = useMemo(() => {
    if (visibleIds.length === 0) {
      return { allVisibleSelected: false, someVisibleSelected: false };
    }
    let hits = 0;
    for (const id of visibleIds) if (selected.has(id)) hits += 1;
    return {
      allVisibleSelected: hits === visibleIds.length,
      someVisibleSelected: hits > 0 && hits < visibleIds.length,
    };
  }, [visibleIds, selected]);

  return useMemo(
    () => ({
      selected,
      selectedIds: Array.from(selected),
      count: selected.size,
      isSelected: (id: number) => selected.has(id),
      toggle,
      toggleAllVisible,
      clear,
      allVisibleSelected,
      someVisibleSelected,
    }),
    [selected, toggle, toggleAllVisible, clear, allVisibleSelected, someVisibleSelected],
  );
}
