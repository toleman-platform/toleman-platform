import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ListRow, ListRows, SelectAllVisible } from "./list-row";
import { StatCard, StatGrid } from "./stat-card";

describe("ListRow", () => {
  it("cancels the base Card's py-6 so density tokens actually apply", () => {
    // This is the whole reason the component exists: the 48px of padding the
    // base Card adds is unreachable by any density setting, which is what made
    // "Compact" save only 7% in #172.
    const { container } = render(<ListRow>row</ListRow>);
    expect(container.querySelector("[data-slot='card']")?.className).toContain("py-0");
  });

  it("drives row padding from the density token", () => {
    const { container } = render(<ListRow>row</ListRow>);
    const content = container.querySelector("[data-slot='card-content']") as HTMLElement;
    expect(content.style.paddingTop).toBe("var(--density-row-py)");
    expect(content.style.paddingBottom).toBe("var(--density-row-py)");
  });

  it("gives the selection checkbox an accessible name", () => {
    // A column of unlabelled checkboxes announces as "checkbox, checkbox,
    // checkbox" with no clue what is being selected.
    render(
      <ListRow selectable selectLabel="Select finding SQL injection in app.py">
        row
      </ListRow>,
    );
    expect(screen.getByRole("checkbox", { name: "Select finding SQL injection in app.py" })).toBeDefined();
  });

  it("warns in development when a selectable row has no label", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    render(<ListRow selectable>row</ListRow>);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("selectLabel"));
    warn.mockRestore();
  });

  it("reports selection changes", async () => {
    const onChange = vi.fn();
    render(<ListRow selectable selectLabel="Select row" onSelectChange={onChange}>row</ListRow>);
    await userEvent.click(screen.getByRole("checkbox"));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("is operable from the keyboard", async () => {
    const onChange = vi.fn();
    render(<ListRow selectable selectLabel="Select row" onSelectChange={onChange}>row</ListRow>);
    await userEvent.tab();
    expect(document.activeElement).toBe(screen.getByRole("checkbox"));
    await userEvent.keyboard(" ");
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("does not render a checkbox when not selectable", () => {
    render(<ListRow>row</ListRow>);
    expect(screen.queryByRole("checkbox")).toBeNull();
  });
});

describe("ListRows", () => {
  it("takes its gap from the density token", () => {
    // 25 rows of a fixed 8px gap is 200px of extra scroll on a page whose
    // entire purpose is scanning a list.
    const { container } = render(<ListRows><div>a</div></ListRows>);
    expect((container.firstElementChild as HTMLElement).style.gap).toBe("var(--density-list-gap)");
  });
});

describe("SelectAllVisible", () => {
  it("sets indeterminate for a partial selection", () => {
    // `indeterminate` is a DOM property with no JSX attribute, so it is the
    // detail every hand-rolled copy skipped -- leaving a half-selected page
    // showing an empty box.
    render(<SelectAllVisible allSelected={false} someSelected onChange={() => {}} />);
    expect((screen.getByRole("checkbox") as HTMLInputElement).indeterminate).toBe(true);
  });

  it("is checked, not indeterminate, when everything is selected", () => {
    render(<SelectAllVisible allSelected someSelected={false} onChange={() => {}} />);
    const box = screen.getByRole("checkbox") as HTMLInputElement;
    expect(box.checked).toBe(true);
    expect(box.indeterminate).toBe(false);
  });

  it("is labelled and clickable via its text", async () => {
    const onChange = vi.fn();
    render(<SelectAllVisible allSelected={false} someSelected={false} onChange={onChange} />);
    // Clicking the label must toggle the box -- a 16px hit target is not enough.
    await userEvent.click(screen.getByText(/select all on this page/i));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("shows optional match context", () => {
    render(
      <SelectAllVisible allSelected={false} someSelected={false} onChange={() => {}} count="12 of 35 match" />,
    );
    expect(screen.getByText(/12 of 35 match/)).toBeDefined();
  });
});

describe("StatCard", () => {
  it("renders a value and label", () => {
    render(<StatCard label="Open findings" value="1137" />);
    expect(screen.getByText("1137")).toBeDefined();
    expect(screen.getByText("Open findings")).toBeDefined();
  });

  it("renders unknown as an em dash, never as zero", () => {
    // An unscanned repo is not a clean one (#174); an ungenerated AIBOM is not
    // an absence of models (#190). A confident 0 for missing data misinforms.
    render(<StatCard label="Open findings" value="0" unknown unknownHint="never scanned" />);
    expect(screen.getByText("—")).toBeDefined();
    expect(screen.queryByText("0")).toBeNull();
    expect(screen.getByText("never scanned")).toBeDefined();
  });

  it("accepts composite values, not just strings", () => {
    render(
      <StatCard label="Open" value={<span>1137 <b>3H</b></span>} />,
    );
    expect(screen.getByText("3H")).toBeDefined();
  });

  it("hides the decorative icon from assistive tech", () => {
    const Icon = (props: { className?: string }) => <svg {...props} data-testid="icon" />;
    const { container } = render(<StatCard label="x" value="1" icon={Icon} />);
    expect(container.querySelector("[aria-hidden='true']")).not.toBeNull();
  });
});

describe("StatGrid", () => {
  it("stacks to one column on small screens", () => {
    // A four-column grid at 390px produces unreadable slivers.
    const { container } = render(<StatGrid><div>a</div></StatGrid>);
    const cls = (container.firstElementChild as HTMLElement).className;
    expect(cls).toContain("grid-cols-1");
    expect(cls).toContain("sm:grid-cols-2");
    expect(cls).toContain("lg:grid-cols-4");
  });

  it("supports a three-column layout", () => {
    const { container } = render(<StatGrid columns={3}><div>a</div></StatGrid>);
    expect((container.firstElementChild as HTMLElement).className).toContain("lg:grid-cols-3");
  });
});
