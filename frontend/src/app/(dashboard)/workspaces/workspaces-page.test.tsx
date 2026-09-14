import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import WorkspacesPage from "./page";
import type { UseWorkspacePickerResult } from "@/hooks/features/use-workspace-picker";
import type { WorkspaceSummary } from "@/lib/api";

/**
 * The rename affordance was a bare <Pencil> SVG with an onClick, nested inside
 * the row's own <button>. That is unreachable by keyboard, has no role and no
 * accessible name, and is invalid HTML besides. These tests assert the fix the
 * only way that means anything: by driving it from the keyboard.
 */
const { updateWorkspace, createWorkspace } = vi.hoisted(() => ({
  updateWorkspace: vi.fn(),
  createWorkspace: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { updateWorkspace, createWorkspace },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

const picker = vi.hoisted(() => ({ value: null as unknown as UseWorkspacePickerResult }));
vi.mock("@/hooks/features/use-workspace-picker", () => ({
  useWorkspacePicker: () => picker.value,
}));

// The key card and the roles panel each own their own fetching and are
// covered separately; this file is about the row's interaction surface.
vi.mock("./workspace-key-card", () => ({ WorkspaceKeyCard: () => <div data-testid="key-card" /> }));
vi.mock("./workspace-roles", () => ({ WorkspaceRoles: () => <div data-testid="roles" /> }));

// `useWorkspacePicker` exposes the same request twice: flattened fields for a
// caller that only decorates a <select>, and the whole `state` for one handing
// it to <AsyncContent>. This page reads the flattened fields, but a mock that
// omits `state` does not satisfy the hook's return type -- so build both from
// one source here rather than letting the two halves describe different loads.
function loadedPicker(workspaces: WorkspaceSummary[]): UseWorkspacePickerResult {
  const refetch = vi.fn();
  return {
    workspaces,
    workspaceId: workspaces[0]?.id ?? null,
    setWorkspaceId: vi.fn(),
    isLoading: false,
    error: null,
    reload: refetch,
    state: {
      status: "success",
      data: workspaces,
      error: null,
      isRefreshing: false,
      requestId: 1,
      isInitialLoading: false,
      refetch,
    },
  };
}

beforeEach(() => {
  updateWorkspace.mockReset();
  createWorkspace.mockReset();
  updateWorkspace.mockResolvedValue({ id: 1, name: "renamed" });
  picker.value = loadedPicker([
    { id: 1, name: "production", organization_id: 1, enforcement_mode: null },
    { id: 2, name: "staging", organization_id: 1, enforcement_mode: null },
  ]);
});

describe("WorkspacesPage rename affordance", () => {
  it("exposes rename as a named button, not a click handler on an icon", () => {
    render(<WorkspacesPage />);
    expect(screen.getByRole("button", { name: "Rename production" })).toBeDefined();
    expect(screen.getByRole("button", { name: "Rename staging" })).toBeDefined();
  });

  it("can be reached and activated with the keyboard alone", async () => {
    const user = userEvent.setup();
    render(<WorkspacesPage />);

    const rename = screen.getByRole("button", { name: "Rename production" });
    rename.focus();
    expect(document.activeElement).toBe(rename);

    await user.keyboard("{Enter}");
    // The row swapped into its editing form, which the old SVG could never
    // be made to do without a mouse.
    expect(screen.getByLabelText("New name for production")).toBeDefined();
  });

  it("does not nest the rename control inside the row's select button", () => {
    render(<WorkspacesPage />);
    const rename = screen.getByRole("button", { name: "Rename production" });
    expect(rename.closest("button")).toBe(rename);
  });
});
