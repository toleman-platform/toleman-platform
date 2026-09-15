import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SlaRules } from "./sla-rules";

/**
 * M16: the days-to-fix field used to be `<Input defaultValue={...} onBlur={...}>`,
 * committing to the server the instant the field lost focus -- no confirmation,
 * no undo, and a click on literally anything else on the page (including the
 * row's own Delete button) counted as "yes, save this". These cover the
 * replacement: nothing reaches `api.updateSlaRule` until Enter or the
 * checkmark is used explicitly, and Escape (or the X) discards a draft
 * in-place instead.
 */

const { workspaces, groups, slaRules, createSlaRule, updateSlaRule, deleteSlaRule } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  groups: vi.fn(),
  slaRules: vi.fn(),
  createSlaRule: vi.fn(),
  updateSlaRule: vi.fn(),
  deleteSlaRule: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { workspaces, groups, slaRules, createSlaRule, updateSlaRule, deleteSlaRule },
  // Single-workspace fixtures below never collide on name, so the real
  // disambiguation logic (admin.ts's workspaceDisplayName) isn't in play.
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

afterEach(() => {
  workspaces.mockReset();
  groups.mockReset();
  slaRules.mockReset();
  createSlaRule.mockReset();
  updateSlaRule.mockReset();
  deleteSlaRule.mockReset();
});

function rule(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: 10,
    workspace_id: 1,
    group_id: null,
    severity: "Critical",
    days_to_fix: 7,
    created_at: "2024-01-01T00:00:00Z",
    ...over,
  };
}

function setup(rules = [rule()]) {
  workspaces.mockResolvedValue([{ id: 1, name: "Acme", organization_id: 1, enforcement_mode: null }]);
  groups.mockResolvedValue([]);
  slaRules.mockResolvedValue(rules);
}

const daysInput = async () =>
  (await screen.findByLabelText("Days to fix for Critical in Workspace default")) as HTMLInputElement;

describe("SlaRules, editing days-to-fix inline", () => {
  it("does not save on blur alone, unlike the field it replaced", async () => {
    setup();
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "14" } });
    fireEvent.blur(input);

    // A Save/Discard pair appearing is the visible sign the draft is only
    // local; give any stray microtask a turn before asserting the negative.
    await screen.findByRole("button", { name: "Save days to fix for Critical in Workspace default" });
    expect(updateSlaRule).not.toHaveBeenCalled();
  });

  it("commits only once Enter is pressed", async () => {
    setup();
    updateSlaRule.mockResolvedValue(rule({ days_to_fix: 14 }));
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "14" } });
    expect(updateSlaRule).not.toHaveBeenCalled();

    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => expect(updateSlaRule).toHaveBeenCalledWith(10, { days_to_fix: 14 }));
  });

  it("commits only once the checkmark is clicked, as an alternative to Enter", async () => {
    setup();
    updateSlaRule.mockResolvedValue(rule({ days_to_fix: 21 }));
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "21" } });
    fireEvent.click(screen.getByRole("button", { name: "Save days to fix for Critical in Workspace default" }));

    await waitFor(() => expect(updateSlaRule).toHaveBeenCalledWith(10, { days_to_fix: 21 }));
  });

  it("discards the draft on Escape without saving anything", async () => {
    setup();
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "99" } });
    await screen.findByRole("button", { name: "Save days to fix for Critical in Workspace default" });

    fireEvent.keyDown(input, { key: "Escape" });

    expect(input.value).toBe("7");
    expect(updateSlaRule).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Save days to fix for Critical in Workspace default" })).toBeNull();
  });

  it("discards the draft on an explicit click of the X, restoring the committed value", async () => {
    setup();
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "30" } });
    fireEvent.click(
      await screen.findByRole("button", { name: "Discard unsaved days to fix for Critical in Workspace default" }),
    );

    expect(input.value).toBe("7");
    expect(updateSlaRule).not.toHaveBeenCalled();
  });

  it("never saves the zero-day SLA the create form was hardened against, even from Enter", async () => {
    setup();
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "0" } });
    fireEvent.keyDown(input, { key: "Enter" });

    const saveButton = (await screen.findByRole("button", {
      name: "Save days to fix for Critical in Workspace default",
    })) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);
    expect(updateSlaRule).not.toHaveBeenCalled();
  });

  it("never saves an emptied field, mirroring the create form's own guard", async () => {
    setup();
    render(<SlaRules />);

    const input = await daysInput();
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.keyDown(input, { key: "Enter" });

    const saveButton = (await screen.findByRole("button", {
      name: "Save days to fix for Critical in Workspace default",
    })) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);
    expect(updateSlaRule).not.toHaveBeenCalled();
  });
});
