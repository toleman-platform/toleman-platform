import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import ReportsPage from "./page";
import { renderWithWorkspace } from "@/test/render-with-workspace";

const {
  targets,
  groups,
  findingTools,
  findingCategories,
  findingEnvironments,
  findingOwners,
  reportSections,
  workspaces,
} = vi.hoisted(() => ({
  targets: vi.fn(),
  groups: vi.fn(),
  findingTools: vi.fn(),
  findingCategories: vi.fn(),
  findingEnvironments: vi.fn(),
  findingOwners: vi.fn(),
  reportSections: vi.fn(),
  // The Scope picker now reads the global workspace switcher (#520), which
  // needs a WorkspaceProvider ancestor -- see renderWithWorkspace below.
  workspaces: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: {
    targets,
    groups,
    findingTools,
    findingCategories,
    findingEnvironments,
    findingOwners,
    reportSections,
    workspaces,
    exportPostureReport: vi.fn(),
  },
}));

beforeEach(() => {
  workspaces.mockResolvedValue([]);
});

// These are decoration (#302): the page degrades to "no filter offered" if
// any of them fail, which is not what item 2 is about, so every test below
// resolves them to keep that noise out of the assertions.
function resolveDecorativeFacets() {
  groups.mockResolvedValue([]);
  findingTools.mockResolvedValue([]);
  findingCategories.mockResolvedValue([]);
  findingEnvironments.mockResolvedValue([]);
  findingOwners.mockResolvedValue([]);
  reportSections.mockResolvedValue([]);
}

// admin M23: a rejected GET /api/targets used to be swallowed by `targets ??
// []`, indistinguishable from "this workspace has zero repositories" --
// Generate went quietly disabled and nothing on screen said why.
describe("Reports page targets fetch", () => {
  it("tells the operator the scope picker failed to load, rather than acting like there are no targets", async () => {
    resolveDecorativeFacets();
    targets.mockRejectedValue(new Error("network error"));

    renderWithWorkspace(<ReportsPage />);

    const banner = await screen.findByRole("alert");
    expect(banner.textContent).toContain("Targets");
    expect(banner.textContent).toContain("is unavailable");
    expect(banner.textContent).toContain("scope picker can't list your repositories");

    const generateButton = screen.getByRole("button", { name: /Generate Report/i }) as HTMLButtonElement;
    expect(generateButton.disabled).toBe(true);
  });

  it("does not crash the page -- the rejection is caught by useAsyncData, not left uncaught", async () => {
    resolveDecorativeFacets();
    targets.mockRejectedValue(new Error("network error"));

    renderWithWorkspace(<ReportsPage />);

    // The rest of the generator (format toggle, severity/state filters) must
    // still render: only the Scope control degrades, not the whole page.
    expect(screen.getByText("Compliance Reports")).not.toBeNull();
    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByRole("alert")).not.toBeNull();
  });

  it("shows no failure banner when the workspace genuinely has zero targets", async () => {
    resolveDecorativeFacets();
    targets.mockResolvedValue([]);

    renderWithWorkspace(<ReportsPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers a retry that re-issues the targets request rather than a full page reload", async () => {
    resolveDecorativeFacets();
    // `mockRejectedValueOnce` then a PERSISTENT resolve, not a second
    // `...Once`: exactly two queued responses is a bet on the fetcher being
    // invoked exactly twice, and the mount effect can consume both before the
    // retry is ever clicked -- the retry then hits an unmocked third call and
    // the count never settles on 2, so waitFor spins to its timeout. What the
    // test is actually about is that Retry re-issues the request rather than
    // reloading the page, so assert that: the call count grew, and the
    // failure banner cleared.
    targets.mockRejectedValueOnce(new Error("network error"));
    targets.mockResolvedValue([{ id: 1, name: "acme/repo", default_branch: "main" }]);

    renderWithWorkspace(<ReportsPage />);
    await screen.findByRole("alert");
    const callsBeforeRetry = targets.mock.calls.length;

    fireEvent.click(screen.getByRole("button", { name: /Retry/i }));

    await waitFor(() => expect(targets.mock.calls.length).toBeGreaterThan(callsBeforeRetry));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });
});
