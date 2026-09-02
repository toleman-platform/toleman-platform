import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { BulkActionBar } from "./bulk-action-bar";

describe("BulkActionBar", () => {
  it("renders nothing when count is 0", () => {
    const { container } = render(
      <BulkActionBar count={0} onClear={vi.fn()} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("announces count with role='status' and aria-live='polite'", () => {
    render(<BulkActionBar count={3} onClear={vi.fn()} />);
    const bar = screen.getByRole("status");
    expect(bar).toBeTruthy();
    expect(bar.getAttribute("aria-live")).toBe("polite");
    expect(screen.getByText("3 items selected")).toBeTruthy();
  });

  it("formats singular vs plural item noun correctly", () => {
    const { rerender } = render(
      <BulkActionBar count={1} itemNoun="finding" onClear={vi.fn()} />
    );
    expect(screen.getByText("1 finding selected")).toBeTruthy();

    rerender(<BulkActionBar count={5} itemNoun="finding" onClear={vi.fn()} />);
    expect(screen.getByText("5 findings selected")).toBeTruthy();
  });

  it("calls onClear when clear button is clicked", () => {
    const onClear = vi.fn();
    render(<BulkActionBar count={2} onClear={onClear} />);
    const clearBtn = screen.getByRole("button", { name: "Clear selection" });
    fireEvent.click(clearBtn);
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("calls onClear when Escape key is pressed", () => {
    const onClear = vi.fn();
    render(<BulkActionBar count={4} onClear={onClear} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("renders children slot", () => {
    render(
      <BulkActionBar count={2} onClear={vi.fn()}>
        <input data-testid="shared-reason" placeholder="Reason for change" />
      </BulkActionBar>
    );
    expect(screen.getByTestId("shared-reason")).toBeTruthy();
  });

  it("renders action buttons and handles clicks", () => {
    const onDismiss = vi.fn();
    const onDelete = vi.fn();
    render(
      <BulkActionBar
        count={3}
        onClear={vi.fn()}
        actions={[
          { label: "Dismiss", onClick: onDismiss },
          { label: "Delete", onClick: onDelete, destructive: true, disabled: false },
        ]}
      />
    );

    const dismissBtn = screen.getByRole("button", { name: "Dismiss" });
    fireEvent.click(dismissBtn);
    expect(onDismiss).toHaveBeenCalledTimes(1);

    const deleteBtn = screen.getByRole("button", { name: "Delete" });
    expect(deleteBtn.className).toContain("destructive");
    fireEvent.click(deleteBtn);
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("respects disabled action buttons", () => {
    const onClick = vi.fn();
    render(
      <BulkActionBar
        count={2}
        onClear={vi.fn()}
        actions={[{ label: "Export", onClick, disabled: true }]}
      />
    );
    const exportBtn = screen.getByRole("button", { name: "Export" });
    expect(exportBtn.hasAttribute("disabled")).toBe(true);
    fireEvent.click(exportBtn);
    expect(onClick).not.toHaveBeenCalled();
  });
});
