import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ConfirmDialog } from "./confirm-dialog";

describe("ConfirmDialog", () => {
  it("renders nothing when open is false", () => {
    const { container } = render(
      <ConfirmDialog
        open={false}
        title="Delete SLA rule?"
        description="This cannot be undone."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders with alertdialog semantics wired to its title and description", () => {
    render(
      <ConfirmDialog
        open={true}
        title="Revoke API key?"
        description="Any integration using it will start failing immediately."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).not.toBeNull();
    expect(dialog.getAttribute("aria-labelledby")).toBe("confirm-dialog-title");
    expect(dialog.getAttribute("aria-describedby")).toBe("confirm-dialog-description");
    expect(screen.getByText("Revoke API key?")).not.toBeNull();
  });

  // admin L8: the sharpest finding in this group. These dialogs gate
  // destructive/consequential actions, so a keyboard user pressing Enter
  // right after one opens must not land on Confirm by default.
  it("focuses Cancel, not Confirm, on open", () => {
    render(
      <ConfirmDialog
        open={true}
        title="Delete SLA rule?"
        description="Findings under it fall back to the workspace default."
        tone="destructive"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));
  });

  it("calls onCancel on backdrop mousedown, but not on panel mousedown", () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Downgrade enforcement?"
        description="Blocking scans become advisory."
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />
    );
    fireEvent.mouseDown(screen.getByRole("alertdialog"));
    expect(onCancel).not.toHaveBeenCalled();

    // The backdrop is the portal's outer overlay div, the alertdialog's parent.
    const backdrop = screen.getByRole("alertdialog").parentElement as HTMLElement;
    fireEvent.mouseDown(backdrop);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("calls onCancel and onConfirm from their respective buttons", () => {
    const onCancel = vi.fn();
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Delete target?"
        description="All of its findings are deleted too."
        onConfirm={onConfirm}
        onCancel={onCancel}
      />
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("calls onCancel on Escape", () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Delete target?"
        description="All of its findings are deleted too."
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  // core M4: the Escape handler used to live on `document` with nothing
  // stopping propagation, so the same keypress that cancelled the dialog
  // also reached a `window` Escape listener behind it -- in the app, that's
  // BulkActionBar's "Esc clears the batch selection" shortcut. A destructive
  // confirmation opened over a bulk selection must not silently discard the
  // selection it is asking the user about.
  it("does not let Escape reach a window listener behind it", () => {
    const onCancel = vi.fn();
    const windowListener = vi.fn();
    window.addEventListener("keydown", windowListener);
    render(
      <ConfirmDialog
        open={true}
        title="Delete 12 findings?"
        description="Triaged findings are marked accepted risk."
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    window.removeEventListener("keydown", windowListener);

    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(windowListener).not.toHaveBeenCalled();
  });

  it("traps Tab focus cycling between Cancel and Confirm", () => {
    render(
      <ConfirmDialog
        open={true}
        title="Delete target?"
        description="All of its findings are deleted too."
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    const cancelBtn = screen.getByRole("button", { name: "Cancel" });
    const confirmBtn = screen.getByRole("button", { name: "Confirm" });

    expect(document.activeElement).toBe(cancelBtn);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(confirmBtn);

    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(cancelBtn);
  });

  it("restores focus to the trigger once closed", () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Delete</button>
          <ConfirmDialog
            open={open}
            title="Delete target?"
            description="All of its findings are deleted too."
            onConfirm={() => setOpen(false)}
            onCancel={() => setOpen(false)}
          />
        </>
      );
    }
    render(<Harness />);

    const trigger = screen.getByRole("button", { name: "Delete" });
    trigger.focus();
    fireEvent.click(trigger);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(document.activeElement).toBe(trigger);
  });
});
