"use client";

import { useCallback, useMemo, useState } from "react";

/**
 * Page-scoped multi-selection. visibleIds must contain only rendered page rows;
 * select-all and allSelected operate on that page, never on hidden filtered results.
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
  /** Every visible row is selected. False for an empty page, "all of
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
