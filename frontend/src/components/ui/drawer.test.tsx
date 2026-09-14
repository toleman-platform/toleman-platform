import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Drawer } from "./drawer";
import { Button } from "./button";

describe("Drawer", () => {
  it("renders nothing when open is false", () => {
    const { container } = render(
      <Drawer open={false} onClose={vi.fn()}>
        Drawer content
      </Drawer>
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders dialog with proper accessibility attributes when open", () => {
    render(
      <Drawer open={true} onClose={vi.fn()} title="Inspection Details">
        <p>Details about vulnerability CVE-2024-1234</p>
      </Drawer>
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog).toBeTruthy();
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.getAttribute("aria-labelledby")).toBe("drawer-title");
    expect(screen.getByRole("heading", { name: "Inspection Details" })).toBeTruthy();
    expect(screen.getByText("Details about vulnerability CVE-2024-1234")).toBeTruthy();
  });

  it("renders description and footer actions", () => {
    render(
      <Drawer
        open={true}
        onClose={vi.fn()}
        title="Audit Event"
        description="Event ID: 99824"
        footer={
          <>
            <Button variant="outline">Cancel</Button>
            <Button>Approve</Button>
          </>
        }
      >
        Body content
      </Drawer>
    );
    expect(screen.getByText("Event ID: 99824")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Approve" })).toBeTruthy();
  });

  it("calls onClose when the close button is clicked", () => {
    const onClose = vi.fn();
    render(
      <Drawer open={true} onClose={onClose} title="Drawer Title">
        Content
      </Drawer>
    );
    const closeBtn = screen.getByRole("button", { name: "Close drawer" });
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onClose when Escape key is pressed", () => {
    const onClose = vi.fn();
    render(
      <Drawer open={true} onClose={onClose}>
        Content
      </Drawer>
    );
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onClose on backdrop click, but not on drawer body click", () => {
    const onClose = vi.fn();
    render(
      <Drawer open={true} onClose={onClose}>
        <div data-testid="drawer-inner-content">Inside Drawer</div>
      </Drawer>
    );
    const dialog = screen.getByRole("dialog");
    const inner = screen.getByTestId("drawer-inner-content");

    // Click inside should not trigger onClose
    fireEvent.click(inner);
    expect(onClose).not.toHaveBeenCalled();

    // Click on backdrop should trigger onClose
    fireEvent.click(dialog);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("locks and restores document.body overflow style", () => {
    const { unmount } = render(
      <Drawer open={true} onClose={vi.fn()}>
        Content
      </Drawer>
    );
    expect(document.body.style.overflow).toBe("hidden");

    unmount();
    expect(document.body.style.overflow).not.toBe("hidden");
  });
});
