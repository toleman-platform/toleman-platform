import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useSelection } from "./use-selection";

describe("useSelection", () => {
  it("starts empty", () => {
    const { result } = renderHook(() => useSelection([1, 2, 3]));
    expect(result.current.count).toBe(0);
    expect(result.current.allVisibleSelected).toBe(false);
  });

  it("toggles a single row on and off", () => {
    const { result } = renderHook(() => useSelection([1, 2, 3]));
    act(() => result.current.toggle(2, true));
    expect(result.current.isSelected(2)).toBe(true);
    expect(result.current.selectedIds).toEqual([2]);

    act(() => result.current.toggle(2, false));
    expect(result.current.isSelected(2)).toBe(false);
    expect(result.current.count).toBe(0);
  });

  it("selects only the visible page, never the whole result set", () => {
    // This is the #204 bug made structural. Select-all previously acted on
    // the filtered list while the page showed a slice, so ticking one box
    // silently selected rows the user could not see.
    const page = [1, 2, 3];
    const { result } = renderHook(() => useSelection(page));
    act(() => result.current.toggleAllVisible(true));
    expect(result.current.selectedIds.sort()).toEqual([1, 2, 3]);
    expect(result.current.selectedIds).not.toContain(4);
  });

  it("keeps selections made on other pages when clearing the current one", () => {
    // Paging away and back should not silently drop what you picked.
    const { rerender, result } = renderHook(({ ids }) => useSelection(ids), {
      initialProps: { ids: [1, 2] },
    });
    act(() => result.current.toggleAllVisible(true));

    rerender({ ids: [3, 4] });
    act(() => result.current.toggleAllVisible(true));
    expect(result.current.count).toBe(4);

    act(() => result.current.toggleAllVisible(false));
    // Page two cleared; page one's selection survives.
    expect(result.current.selectedIds.sort()).toEqual([1, 2]);
  });

  it("reports allVisibleSelected against the current page only", () => {
    const { rerender, result } = renderHook(({ ids }) => useSelection(ids), {
      initialProps: { ids: [1, 2] },
    });
    act(() => result.current.toggleAllVisible(true));
    expect(result.current.allVisibleSelected).toBe(true);

    // Same selection, different page: the header box must not claim
    // everything here is selected.
    rerender({ ids: [3, 4] });
    expect(result.current.allVisibleSelected).toBe(false);
  });

  it("reports the indeterminate case", () => {
    const { result } = renderHook(() => useSelection([1, 2, 3]));
    act(() => result.current.toggle(1, true));
    expect(result.current.someVisibleSelected).toBe(true);
    expect(result.current.allVisibleSelected).toBe(false);

    act(() => {
      result.current.toggle(2, true);
      result.current.toggle(3, true);
    });
    expect(result.current.someVisibleSelected).toBe(false);
    expect(result.current.allVisibleSelected).toBe(true);
  });

  it("does not report an empty page as fully selected", () => {
    // "All of nothing" rendering as a ticked box is a small lie that makes
    // the bulk bar appear for zero rows.
    const { result } = renderHook(() => useSelection([]));
    expect(result.current.allVisibleSelected).toBe(false);
    expect(result.current.someVisibleSelected).toBe(false);
  });

  it("clears everything across all pages", () => {
    const { rerender, result } = renderHook(({ ids }) => useSelection(ids), {
      initialProps: { ids: [1, 2] },
    });
    act(() => result.current.toggleAllVisible(true));
    rerender({ ids: [3, 4] });
    act(() => result.current.toggleAllVisible(true));
    expect(result.current.count).toBe(4);

    act(() => result.current.clear());
    expect(result.current.count).toBe(0);
  });

  it("is idempotent when selecting an already-selected row", () => {
    const { result } = renderHook(() => useSelection([1]));
    act(() => result.current.toggle(1, true));
    act(() => result.current.toggle(1, true));
    expect(result.current.count).toBe(1);
  });
});
