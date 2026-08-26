import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AsyncContent } from "./async-content";

/**
 * Accessibility asserted rather than claimed. Every announcement, aria-busy
 * state and keyboard path below is checked against a real DOM, a component
 * that merely *says* it is accessible in a docblock is not.
 */
type State = React.ComponentProps<typeof AsyncContent<string[]>>["state"];

function stateOf(over: Partial<State> = {}): State {
  return {
    status: "success",
    data: [],
    error: null,
    isRefreshing: false,
    isInitialLoading: false,
    refetch: vi.fn(),
    ...over,
  };
}

const renderList = (data: string[]) => <ul>{data.map((d) => <li key={d}>{d}</li>)}</ul>;

describe("AsyncContent", () => {
  it("renders data when loaded", () => {
    render(
      <AsyncContent state={stateOf({ data: ["alpha", "beta"] })} itemNoun="findings">
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("alpha")).toBeDefined();
    expect(screen.getByText("beta")).toBeDefined();
  });

  // --- announcements -------------------------------------------------------

  it("announces the loading state", () => {
    render(
      <AsyncContent
        state={stateOf({ status: "loading", data: null, isInitialLoading: true })}
        itemNoun="findings"
      >
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("Loading findings")).toBeDefined();
  });

  it("announces how many items loaded", () => {
    // Swapping a skeleton for a list is silent to a screen reader; the count
    // is the thing that confirms the action did something.
    render(
      <AsyncContent state={stateOf({ data: ["a", "b", "c"] })} itemNoun="findings">
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("Loaded 3 findings")).toBeDefined();
  });

  it("announces an empty result", () => {
    render(
      <AsyncContent state={stateOf({ data: [] })} itemNoun="findings">
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("No findings found")).toBeDefined();
  });

  it("announces a failure", () => {
    render(
      <AsyncContent
        state={stateOf({ status: "error", data: null, error: new Error("network down") })}
        itemNoun="findings"
      >
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("Failed to load findings")).toBeDefined();
  });

  it("uses a polite live region so it does not interrupt", () => {
    // Loading a list should not talk over whatever the user is reading.
    const { container } = render(
      <AsyncContent state={stateOf({ data: ["a"] })}>{renderList}</AsyncContent>,
    );
    const live = container.querySelector("[aria-live]");
    expect(live?.getAttribute("aria-live")).toBe("polite");
    expect(live?.getAttribute("aria-atomic")).toBe("true");
  });

  it("keeps the live region mounted while idle", () => {
    // A live region inserted at the same moment its text appears is commonly
    // missed by assistive tech; it has to already be in the document.
    const { container } = render(
      <AsyncContent state={stateOf({ status: "idle", data: null })}>{renderList}</AsyncContent>,
    );
    expect(container.querySelector("[aria-live='polite']")).not.toBeNull();
  });

  // --- aria-busy -----------------------------------------------------------

  it("marks itself busy during a background refresh", () => {
    // Refreshing keeps old rows on screen, so nothing visual signals
    // staleness. aria-busy says so without a spinner.
    const { container } = render(
      <AsyncContent state={stateOf({ status: "loading", data: ["a"], isRefreshing: true })}>
        {renderList}
      </AsyncContent>,
    );
    expect(container.firstElementChild?.getAttribute("aria-busy")).toBe("true");
  });

  it("is not busy once settled", () => {
    const { container } = render(
      <AsyncContent state={stateOf({ data: ["a"] })}>{renderList}</AsyncContent>,
    );
    expect(container.firstElementChild?.getAttribute("aria-busy")).toBe("false");
  });

  // --- empty vs filtered-empty --------------------------------------------

  it("offers a clear-filters exit when filtered to nothing", async () => {
    // Not the same problem as "nothing exists yet", and not the same exit.
    const onClear = vi.fn();
    render(
      <AsyncContent state={stateOf({ data: [] })} isFiltered onClearFilters={onClear} itemNoun="findings">
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("No findings match these filters")).toBeDefined();
    await userEvent.click(screen.getByRole("button", { name: /clear filters/i }));
    expect(onClear).toHaveBeenCalledOnce();
  });

  it("does not tell a first-time user to clear filters they never set", () => {
    render(
      <AsyncContent state={stateOf({ data: [] })} itemNoun="findings">
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("No findings yet")).toBeDefined();
    expect(screen.queryByRole("button", { name: /clear filters/i })).toBeNull();
  });

  // --- errors and recovery -------------------------------------------------

  it("surfaces the error message and a working retry", async () => {
    const refetch = vi.fn();
    render(
      <AsyncContent state={stateOf({ status: "error", data: null, error: new Error("boom"), refetch })}>
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText(/boom/)).toBeDefined();
    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(refetch).toHaveBeenCalledOnce();
  });

  it("shows stale data with an alert when a refresh fails, rather than blanking", async () => {
    const refetch = vi.fn();
    render(
      <AsyncContent
        state={stateOf({ status: "error", data: ["cached"], error: new Error("offline"), refetch })}
      >
        {renderList}
      </AsyncContent>,
    );
    expect(screen.getByText("cached")).toBeDefined();
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("offline");
    await userEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(refetch).toHaveBeenCalledOnce();
  });

  it("is reachable by keyboard alone", async () => {
    // Retry must be operable without a mouse.
    const refetch = vi.fn();
    render(
      <AsyncContent state={stateOf({ status: "error", data: null, error: new Error("x"), refetch })}>
        {renderList}
      </AsyncContent>,
    );
    await userEvent.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: /try again/i }));
    await userEvent.keyboard("{Enter}");
    expect(refetch).toHaveBeenCalled();
  });

  // --- edge cases ----------------------------------------------------------

  it("supports a custom emptiness test for non-array payloads", () => {
    render(
      <AsyncContent
        state={{ ...stateOf(), data: { items: [] } } as never}
        isEmpty={(d: { items: unknown[] }) => d.items.length === 0}
        itemNoun="records"
      >
        {() => <div>never rendered</div>}
      </AsyncContent>,
    );
    expect(screen.getByText("No records yet")).toBeDefined();
  });

  it("renders nothing but the live region while idle", () => {
    // A deferred request must not fake a spinner for something nobody asked
    // for yet.
    render(
      <AsyncContent state={stateOf({ status: "idle", data: null })}>
        {() => <div>content</div>}
      </AsyncContent>,
    );
    expect(screen.queryByText("content")).toBeNull();
  });
});
