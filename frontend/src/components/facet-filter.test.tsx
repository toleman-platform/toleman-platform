import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FacetFilter } from "./facet-filter";

const push = vi.fn();
let currentSearch = "";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(currentSearch),
}));

const OPTIONS = [
  { value: "Critical", label: "Critical", count: 12 },
  { value: "High", label: "High", count: 4 },
  { value: "Low", label: "Low", count: 0 },
];

function pushedUrl(call = 0) {
  return new URL(push.mock.calls[call][0], "http://x");
}

beforeEach(() => {
  push.mockReset();
  currentSearch = "";
});

describe("FacetFilter", () => {
  it("shows every option's count without anything being opened", () => {
    // The whole point of #270: the numbers are on the page, not behind a
    // dropdown you have to operate to learn what is in it.
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    expect(screen.getByRole("button", { name: /Critical/ }).textContent).toContain("12");
    expect(screen.getByRole("button", { name: /High/ }).textContent).toContain("4");
  });

  it("keeps the count from running into the option's accessible name", () => {
    // The label and the count are adjacent inline spans, so the computed
    // name concatenated them: the "tool-0" pill showing 0 announced as
    // "tool-00", ambiguous with the "tool-00" that does not exist and
    // unaddressable by anything that looks a control up by name.
    render(
      <FacetFilter
        label="Tool"
        paramKey="tool"
        options={[{ value: "tool-0", label: "tool-0", count: 0 }]}
      />,
    );
    expect(screen.getByRole("button", { name: "tool-0, 0 findings" })).toBeTruthy();
  });

  it("renders a zero-count option rather than hiding it", () => {
    // "Nothing matches this right now" and "this dimension doesn't exist"
    // are different facts.
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    expect(screen.getByRole("button", { name: /Low/ }).textContent).toContain("0");
  });

  it("renders nothing at all when the dimension has no options", () => {
    const { container } = render(<FacetFilter label="Owner" paramKey="owner" options={[]} />);
    expect(container.textContent).toBe("");
  });

  it("shows no number when the count is unknown rather than printing 0", () => {
    // The degraded path: the facets call failed and the options came from
    // the plain option-list endpoint. "0" would be a specific, false claim.
    render(
      <FacetFilter
        label="Tool"
        paramKey="tool"
        options={[{ value: "semgrep", label: "semgrep", count: null }]}
      />,
    );
    expect(screen.getByRole("button", { name: /semgrep/ }).textContent).toBe("semgrep");
  });

  it("still renders a selected value the option list does not contain", async () => {
    // Otherwise an active ?tool=semgrep survives in the URL and keeps
    // narrowing the list with no control left to switch it off.
    currentSearch = "tool=semgrep";
    render(<FacetFilter label="Tool" paramKey="tool" options={[]} />);

    const pill = screen.getByRole("button", { name: /semgrep/ });
    expect(pill.getAttribute("aria-pressed")).toBe("true");
    await userEvent.click(pill);
    expect(pushedUrl().searchParams.getAll("tool")).toEqual([]);
  });

  it("marks the selected options as pressed", () => {
    currentSearch = "severity=Critical";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    // Plain attribute checks: this project does not load jest-dom matchers.
    expect(screen.getByRole("button", { name: /Critical/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: /High/ }).getAttribute("aria-pressed")).toBe("false");
  });

  it("adds a second value as a repeated query param, keeping the first", async () => {
    currentSearch = "severity=Critical";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button", { name: /High/ }));

    expect(pushedUrl().searchParams.getAll("severity")).toEqual(["Critical", "High"]);
  });

  it("clicking a selected option removes just that value", async () => {
    currentSearch = "severity=Critical&severity=High";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button", { name: /Critical/ }));

    expect(pushedUrl().searchParams.getAll("severity")).toEqual(["High"]);
  });

  it("a zero-count option is still clickable", async () => {
    // Same call the category tabs make about an empty tab: an empty result
    // is a legitimate, linkable destination.
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button", { name: /Low/ }));

    expect(pushedUrl().searchParams.getAll("severity")).toEqual(["Low"]);
  });

  it("leaves other filters alone and resets paging", async () => {
    currentSearch = "tool=semgrep&page=3";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button", { name: /Critical/ }));

    const url = pushedUrl();
    expect(url.searchParams.get("tool")).toBe("semgrep");
    expect(url.searchParams.has("page")).toBe(false);
  });

  it("Clear removes every value for this facet only", async () => {
    currentSearch = "severity=Critical&severity=High&tool=semgrep";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));

    const url = pushedUrl();
    expect(url.searchParams.getAll("severity")).toEqual([]);
    expect(url.searchParams.get("tool")).toBe("semgrep");
  });

  it("offers no Clear button when nothing in this facet is selected", () => {
    currentSearch = "tool=semgrep";
    render(<FacetFilter label="Severity" paramKey="severity" options={OPTIONS} />);
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
  });

  const LONG = Array.from({ length: 9 }, (_, i) => ({
    value: `tool-${i}`,
    label: `tool-${i}`,
    count: i,
  }));

  it("collapses a long option list behind a '+N more' control", () => {
    render(<FacetFilter label="Tool" paramKey="tool" options={LONG} visibleCount={6} />);
    // Both halves of the invariant: the first `visibleCount` are shown...
    for (const i of [0, 1, 2, 3, 4, 5]) {
      expect(screen.getByRole("button", { name: new RegExp(`tool-${i}\\b`) })).toBeTruthy();
    }
    // ...and exactly the rest are behind the control.
    for (const i of [6, 7, 8]) {
      expect(screen.queryByRole("button", { name: new RegExp(`tool-${i}\\b`) })).toBeNull();
    }
    expect(screen.getByRole("button", { name: "+3 more" })).toBeTruthy();
  });

  it("expands to the full list on demand", async () => {
    render(<FacetFilter label="Tool" paramKey="tool" options={LONG} visibleCount={6} />);
    await userEvent.click(screen.getByRole("button", { name: "+3 more" }));
    expect(screen.getByRole("button", { name: /tool-8/ })).toBeTruthy();
  });

  it("never hides an option that is currently selected", () => {
    // The one filter you are actually using must not be the one behind
    // "+N more".
    currentSearch = "tool=tool-8";
    render(<FacetFilter label="Tool" paramKey="tool" options={LONG} visibleCount={6} />);
    expect(screen.getByRole("button", { name: /tool-8/ }).getAttribute("aria-pressed")).toBe("true");
  });
});
