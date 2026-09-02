import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { FilterBar } from "./filter-bar";
import { Button } from "./button";

describe("FilterBar", () => {
  it("renders search input with value and placeholder", () => {
    const onSearchChange = vi.fn();
    render(
      <FilterBar
        searchValue="critical"
        onSearchChange={onSearchChange}
        searchPlaceholder="Filter findings..."
      />
    );
    const input = screen.getByPlaceholderText("Filter findings...") as HTMLInputElement;
    expect(input.value).toBe("critical");

    fireEvent.change(input, { target: { value: "high" } });
    expect(onSearchChange).toHaveBeenCalledWith("high");
  });

  it("renders search clear button when searchValue is present", () => {
    const onSearchChange = vi.fn();
    render(
      <FilterBar
        searchValue="sql injection"
        onSearchChange={onSearchChange}
      />
    );
    const clearSearchBtn = screen.getByRole("button", { name: "Clear search" });
    fireEvent.click(clearSearchBtn);
    expect(onSearchChange).toHaveBeenCalledWith("");
  });

  it("does not render search clear button when searchValue is empty", () => {
    render(<FilterBar searchValue="" onSearchChange={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Clear search" })).toBeNull();
  });

  it("renders custom filters and actions slots", () => {
    render(
      <FilterBar
        filters={<div data-testid="custom-filter-dropdown">Filter Dropdown</div>}
        actions={<Button>Export</Button>}
      />
    );
    expect(screen.getByTestId("custom-filter-dropdown")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Export" })).toBeTruthy();
  });

  it("renders active filter pills and handles pill removal", () => {
    const removeSeverity = vi.fn();
    const removeTool = vi.fn();

    render(
      <FilterBar
        activePills={[
          { id: "1", label: "Severity", value: "High", onRemove: removeSeverity },
          { id: "2", label: "Tool", value: "Semgrep", onRemove: removeTool },
        ]}
      />
    );

    expect(screen.getByText("Active filters:")).toBeTruthy();
    expect(screen.getByText("Severity:")).toBeTruthy();
    expect(screen.getByText("High")).toBeTruthy();
    expect(screen.getByText("Tool:")).toBeTruthy();
    expect(screen.getByText("Semgrep")).toBeTruthy();

    const removeSeverityBtn = screen.getByRole("button", {
      name: "Remove filter Severity High",
    });
    fireEvent.click(removeSeverityBtn);
    expect(removeSeverity).toHaveBeenCalledTimes(1);
    expect(removeTool).not.toHaveBeenCalled();
  });

  it("renders Clear all pills button and triggers onClearAllPills", () => {
    const onClearAll = vi.fn();
    render(
      <FilterBar
        activePills={[
          { id: "1", label: "Status", value: "Open", onRemove: vi.fn() },
        ]}
        onClearAllPills={onClearAll}
      />
    );

    const clearAllBtn = screen.getByRole("button", { name: "Clear all" });
    fireEvent.click(clearAllBtn);
    expect(onClearAll).toHaveBeenCalledTimes(1);
  });
});
