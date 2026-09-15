import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { WorkspaceRoles } from "./workspace-roles";

/**
 * "No workspace-scoped roles assigned" is a claim about who can reach a
 * workspace. The list used to reach it via `memberships === null ||
 * memberships.length === 0`, and `null` is what a failed read leaves behind --
 * so a membership request that never came back told an admin the access list
 * was empty when it may have been full.
 */
const { users, workspaceMemberships, assignWorkspaceRole, removeWorkspaceMembership } = vi.hoisted(() => ({
  users: vi.fn(),
  workspaceMemberships: vi.fn(),
  assignWorkspaceRole: vi.fn(),
  removeWorkspaceMembership: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { users, workspaceMemberships, assignWorkspaceRole, removeWorkspaceMembership },
}));

afterEach(() => {
  users.mockReset();
  workspaceMemberships.mockReset();
  assignWorkspaceRole.mockReset();
  removeWorkspaceMembership.mockReset();
});

function membership(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: 7,
    user_id: 3,
    user_email: "dev@example.com",
    user_name: "Dev Eloper",
    workspace_id: 1,
    workspace_name: "Acme",
    role: "developer",
    ...over,
  };
}

describe("WorkspaceRoles, a read that failed vs a workspace with no assignments", () => {
  it("reports the failure rather than claiming nobody has a scoped role", async () => {
    users.mockResolvedValue([]);
    workspaceMemberships.mockRejectedValue(new Error("memberships endpoint unavailable"));

    render(<WorkspaceRoles workspaceId={1} />);

    expect(await screen.findByText("Couldn't load workspace roles")).toBeTruthy();
    expect(screen.queryByText("No workspace-scoped roles assigned")).toBeNull();
  });

  it("offers a retry that re-runs the read and shows the assignments it returns", async () => {
    users.mockResolvedValue([]);
    workspaceMemberships
      .mockRejectedValueOnce(new Error("memberships endpoint unavailable"))
      .mockResolvedValue([membership()]);

    render(<WorkspaceRoles workspaceId={1} />);
    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));

    expect(await screen.findByText("Dev Eloper")).toBeTruthy();
    expect(screen.queryByText("Couldn't load workspace roles")).toBeNull();
    expect(screen.queryByText("No workspace-scoped roles assigned")).toBeNull();
  });

  it("still says there are none when the read succeeds and returns none", async () => {
    // The other half of the pair: gating the empty state on a successful read
    // must not silence it for the workspace that genuinely has no assignments.
    users.mockResolvedValue([]);
    workspaceMemberships.mockResolvedValue([]);

    render(<WorkspaceRoles workspaceId={1} />);

    expect(await screen.findByText("No workspace-scoped roles assigned")).toBeTruthy();
    expect(screen.queryByText("Couldn't load workspace roles")).toBeNull();
  });
});
