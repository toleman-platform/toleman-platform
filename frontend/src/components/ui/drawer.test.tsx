import { useState } from "react";
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
    // Dispatched on `document`, not `window`: a real keydown bubbles
    // element -> document -> window, and the shared trap (see useFocusTrap
    // in drawer.tsx) listens on `document` specifically so it can stop the
    // event there, before it would otherwise reach a `window` listener like
    // BulkActionBar's Escape-clears-selection shortcut.
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not let Escape reach a window listener behind it", () => {
    // core M4: this is the regression BulkActionBar hit -- its own Escape
    // shortcut lives on `window`, and used to fire alongside the drawer's,
    // clearing state behind the drawer on the same keypress that dismissed
    // it. A `window` listener here stands in for that shortcut without
    // reaching into bulk-action-bar.tsx (out of scope for this change).
    const onClose = vi.fn();
    const windowListener = vi.fn();
    window.addEventListener("keydown", windowListener);
    render(
      <Drawer open={true} onClose={onClose}>
        Content
      </Drawer>
    );
    fireEvent.keyDown(document, { key: "Escape" });
    window.removeEventListener("keydown", windowListener);

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(windowListener).not.toHaveBeenCalled();
  });

  it("moves focus into the drawer on open and restores it on close", () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open drawer</button>
          <Drawer open={open} onClose={() => setOpen(false)} title="Details">
            <button>Inside drawer</button>
          </Drawer>
        </>
      );
    }
    render(<Harness />);

    const trigger = screen.getByRole("button", { name: "Open drawer" });
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(trigger);
    // First focusable element inside the drawer is its own close button.
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close drawer" }));

    fireEvent.keyDown(document, { key: "Escape" });
    expect(document.activeElement).toBe(trigger);
  });

  it("traps Tab focus cycling inside the drawer", () => {
    render(
      <Drawer
        open={true}
        onClose={vi.fn()}
        title="Details"
        footer={<Button>Last action</Button>}
      >
        Content
      </Drawer>
    );

    const closeBtn = screen.getByRole("button", { name: "Close drawer" });
    const lastBtn = screen.getByRole("button", { name: "Last action" });

    // Close button is first-focused on open; Shift+Tab from there should
    // wrap to the last focusable control rather than leaving the drawer.
    expect(document.activeElement).toBe(closeBtn);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(lastBtn);

    // Tab from the last control wraps back to the first.
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(closeBtn);
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
