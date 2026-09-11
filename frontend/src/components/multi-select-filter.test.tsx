import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MultiSelectFilter } from "./multi-select-filter";

const push = vi.fn();
let currentSearch = "";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(currentSearch),
}));

const OPTIONS = [
  { value: "Critical", label: "Critical" },
  { value: "High", label: "High" },
  { value: "Low", label: "Low" },
];

beforeEach(() => {
  push.mockReset();
  currentSearch = "";
});

describe("MultiSelectFilter", () => {
  it("shows the plain label when nothing is selected", () => {
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    expect(screen.getByRole("button", { name: "Filter by all severities" }).textContent).toContain("All severities");
  });

  it("shows the option's own label when exactly one value is selected", () => {
    currentSearch = "severity=Critical";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    expect(screen.getByRole("button").textContent).toContain("Critical");
  });

  it("shows a count once more than one value is selected", () => {
    currentSearch = "severity=Critical&severity=High";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    expect(screen.getByRole("button").textContent).toContain("All severities (2)");
  });

  it("adds a second value as a repeated query param, keeping the first checked", async () => {
    currentSearch = "severity=Critical";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(screen.getByRole("checkbox", { name: "High" }));

    expect(push).toHaveBeenCalledTimes(1);
    const pushedUrl = new URL(push.mock.calls[0][0], "http://x");
    expect(pushedUrl.searchParams.getAll("severity")).toEqual(["Critical", "High"]);
  });

  it("unchecking the only selected value clears the param entirely", async () => {
    currentSearch = "severity=Critical";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(screen.getByRole("checkbox", { name: "Critical" }));

    const pushedUrl = new URL(push.mock.calls[0][0], "http://x");
    expect(pushedUrl.searchParams.getAll("severity")).toEqual([]);
  });

  it("drops the page param when the selection changes", async () => {
    currentSearch = "page=3";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(screen.getByRole("checkbox", { name: "Critical" }));

    const pushedUrl = new URL(push.mock.calls[0][0], "http://x");
    expect(pushedUrl.searchParams.has("page")).toBe(false);
  });

  it("the Clear button removes every value for this filter", async () => {
    currentSearch = "severity=Critical&severity=High&tool=semgrep";
    render(<MultiSelectFilter label="All severities" paramKey="severity" options={OPTIONS} />);
    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));

    const pushedUrl = new URL(push.mock.calls[0][0], "http://x");
    expect(pushedUrl.searchParams.getAll("severity")).toEqual([]);
    // Other filters are untouched.
    expect(pushedUrl.searchParams.get("tool")).toBe("semgrep");
  });
});
