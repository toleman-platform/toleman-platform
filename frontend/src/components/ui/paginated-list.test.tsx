import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { PaginatedList, type PaginatedListProps } from "./paginated-list";

// Only the navigation is mocked; ActivityPagination itself renders for real,
// because the page-size control and the Previous/Next boundaries are exactly
// what this shell is supposed to guarantee to every list that uses it.
const { push, currentQuery } = vi.hoisted(() => ({ push: vi.fn(), currentQuery: { value: "" } }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/sbom",
  useSearchParams: () => new URLSearchParams(currentQuery.value),
}));

type Row = { id: number; name: string };

function rows(count: number): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: i + 1, name: `row-${i + 1}` }));
}

function renderList(overrides: Partial<PaginatedListProps<Row>> = {}) {
  const props: PaginatedListProps<Row> = {
    items: rows(3),
    total: 3,
    page: 1,
    pageSize: 25,
    getKey: (r) => r.id,
    renderItem: (r) => <div>{r.name}</div>,
    itemNoun: "component",
    ...overrides,
  };
  return render(<PaginatedList {...props} />);
}

beforeEach(() => {
  push.mockReset();
  currentQuery.value = "";
});

describe("PaginatedList count line", () => {
  it("counts the whole result set, not the page on screen", () => {
    // The bug this guards: an SBOM of 717 components paged 25 at a time must
    // not announce itself as "25 components".
    renderList({ items: rows(25), total: 717, page: 1, pageSize: 25 });

    expect(screen.getByText("717 components")).not.toBeNull();
    expect(screen.queryByText("25 components")).toBeNull();
  });

  it("uses the singular for exactly one", () => {
    renderList({ items: rows(1), total: 1 });

    expect(screen.getByText("1 component")).not.toBeNull();
    expect(screen.queryByText("1 components")).toBeNull();
  });

  it("accepts an irregular plural", () => {
    renderList({ items: rows(2), total: 2, itemNoun: "entry", itemNounPlural: "entries" });

    expect(screen.getByText("2 entries")).not.toBeNull();
  });

  it("lets a caller replace the generated count outright", () => {
    // The grouped findings list counts two things at once.
    renderList({ summary: "12 decisions across 87 findings" });

    expect(screen.getByText("12 decisions across 87 findings")).not.toBeNull();
    expect(screen.queryByText("3 components")).toBeNull();
  });

  it("renders no count line at all when the caller passes null", () => {
    renderList({ summary: null });

    expect(screen.queryByText("3 components")).toBeNull();
    // The rows are still there; only the count was suppressed.
    expect(screen.getByText("row-1")).not.toBeNull();
  });
});

describe("PaginatedList rows", () => {
  it("stacks rows in the density-aware container by default", () => {
    // A fixed gap is 200px of dead scroll over 25 rows, and no density
    // setting can reach it.
    const { container } = renderList({ items: rows(2), total: 2 });

    const stack = Array.from(container.querySelectorAll("div")).find(
      (el) => (el as HTMLElement).style.gap === "var(--density-list-gap)",
    ) as HTMLElement | undefined;

    expect(stack).toBeTruthy();
    expect(stack?.textContent).toContain("row-1");
    expect(stack?.textContent).toContain("row-2");
  });

  it("hands the rows to a caller-supplied container instead", () => {
    const { container } = renderList({
      items: rows(2),
      total: 2,
      renderRows: (children) => <div role="table">{children}</div>,
    });

    expect(screen.getByRole("table").textContent).toContain("row-1");
    const stacked = Array.from(container.querySelectorAll("div")).some(
      (el) => (el as HTMLElement).style.gap === "var(--density-list-gap)",
    );
    expect(stacked).toBe(false);
  });

  it("shows the empty state in place of the rows, keeping the pager reachable", () => {
    // Overshooting the last page must not strand the reader on a screen with
    // no way back: the empty state replaces the rows, not the whole list.
    renderList({ items: [], total: 57, page: 3, pageSize: 25, empty: <p>Nothing on this page</p> });

    expect(screen.getByText("Nothing on this page")).not.toBeNull();
    expect(screen.queryByText("row-1")).toBeNull();
    expect(screen.getAllByRole("button", { name: "Previous" }).length).toBeGreaterThan(0);
  });

  it("drops the pager entirely for a genuinely empty result set", () => {
    renderList({ items: [], total: 0, empty: <p>No components recorded yet</p> });

    expect(screen.getByText("No components recorded yet")).not.toBeNull();
    expect(screen.queryByRole("button", { name: "Previous" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
  });
});

describe("PaginatedList page size", () => {
  it("writes the chosen size and returns to the first page", () => {
    // Keeping page 4 while growing the page size lands past the end of the
    // result set, which reads as an empty list.
    currentQuery.value = "page=4";
    renderList({ items: rows(25), total: 717, page: 4, pageSize: 25 });

    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), {
      target: { value: "100" },
    });

    expect(push).toHaveBeenCalledTimes(1);
    const url = new URL(push.mock.calls[0][0] as string, "http://localhost");
    expect(url.searchParams.get("page_size")).toBe("100");
    expect(url.searchParams.get("page")).toBe("1");
  });

  it("keeps the size control reachable when the result set fits on one page", () => {
    // Picking 100 on a 40-row list used to hide the pager, and with it the
    // only way back to 25 short of hand-editing the URL. The shell must not
    // re-add that gate around ActivityPagination.
    renderList({ items: rows(40), total: 40, page: 1, pageSize: 100 });

    expect(screen.getByRole("combobox", { name: "Rows per page" })).not.toBeNull();
  });
});

describe("PaginatedList pagination boundaries", () => {
  it("disables Previous on the first page and moves forward from it", () => {
    renderList({ items: rows(25), total: 57, page: 1, pageSize: 25 });

    for (const button of screen.getAllByRole("button", { name: "Previous" })) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
    const next = screen.getAllByRole("button", { name: "Next" });
    expect(next.every((b) => (b as HTMLButtonElement).disabled)).toBe(false);

    fireEvent.click(next[0]);
    const url = new URL(push.mock.calls[0][0] as string, "http://localhost");
    expect(url.searchParams.get("page")).toBe("2");
  });

  it("disables Next on the last page", () => {
    // 57 rows at 25 a page is three pages, the last of them a part page.
    renderList({ items: rows(7), total: 57, page: 3, pageSize: 25 });

    for (const button of screen.getAllByRole("button", { name: "Next" })) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
    expect(screen.getAllByRole("button", { name: "Previous" }).every((b) => (b as HTMLButtonElement).disabled)).toBe(
      false,
    );
  });

  it("reports the range of the part page against the true total", () => {
    renderList({ items: rows(7), total: 57, page: 3, pageSize: 25 });

    // Both pagers state it, and neither may run past the end of the set.
    const shown = screen.getAllByText("Showing 51-57 of 57");
    expect(shown.length).toBe(2);
    expect(screen.getAllByText("Page 3 of 3").length).toBe(2);
  });
});
