import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { WorkspaceSwitcher } from "./workspace-switcher";
import { renderWithWorkspace } from "@/test/render-with-workspace";

/**
 * Issue #506: the global switcher replaces every page-local workspace
 * `<select>` this platform used to have, each of which disambiguated
 * same-named workspaces across organisations (e.g. two orgs both called
 * "default") with a `(#id)` suffix via workspaceDisplayName. This is that
 * coverage's new home -- moved from admin/tool-marketplace.test.tsx, whose
 * own page-local picker this issue removed.
 */
const { workspaces } = vi.hoisted(() => ({ workspaces: vi.fn() }));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, workspaces } };
});

afterEach(() => {
  workspaces.mockReset();
});

describe("WorkspaceSwitcher", () => {
  it("disambiguates two workspaces that share a name", async () => {
    workspaces.mockResolvedValue([
      { id: 1, name: "default", organization_id: 1, enforcement_mode: null },
      { id: 2, name: "default", organization_id: 2, enforcement_mode: null },
    ]);
    renderWithWorkspace(<WorkspaceSwitcher />);

    expect(await screen.findByRole("option", { name: "default (#1)" })).toBeDefined();
    expect(screen.getByRole("option", { name: "default (#2)" })).toBeDefined();
    // A bare "default" with no id suffix would mean the old, ambiguous label
    // is still leaking through for one of the two rows.
    expect(screen.queryByRole("option", { name: "default" })).toBeNull();
  });

  it("leaves a workspace's name alone when nothing else in the list collides", async () => {
    workspaces.mockResolvedValue([
      { id: 1, name: "production", organization_id: 1, enforcement_mode: null },
      { id: 2, name: "staging", organization_id: 1, enforcement_mode: null },
    ]);
    renderWithWorkspace(<WorkspaceSwitcher />);

    expect(await screen.findByRole("option", { name: "production" })).toBeDefined();
    expect(screen.getByRole("option", { name: "staging" })).toBeDefined();
  });

  it("always offers an All workspaces option", async () => {
    workspaces.mockResolvedValue([{ id: 1, name: "production", organization_id: 1, enforcement_mode: null }]);
    renderWithWorkspace(<WorkspaceSwitcher />);

    expect(await screen.findByRole("option", { name: "All workspaces" })).toBeDefined();
  });
});
