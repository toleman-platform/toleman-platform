import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import ReportsPage from "./page";

const { targets, groups, findingTools, findingCategories, findingEnvironments, findingOwners, reportSections } =
  vi.hoisted(() => ({
    targets: vi.fn(),
    groups: vi.fn(),
    findingTools: vi.fn(),
    findingCategories: vi.fn(),
    findingEnvironments: vi.fn(),
    findingOwners: vi.fn(),
    reportSections: vi.fn(),
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
    exportPostureReport: vi.fn(),
  },
}));

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

    render(<ReportsPage />);

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

    render(<ReportsPage />);

    // The rest of the generator (format toggle, severity/state filters) must
    // still render: only the Scope control degrades, not the whole page.
    expect(screen.getByText("Compliance Reports")).not.toBeNull();
    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(await screen.findByRole("alert")).not.toBeNull();
  });

  it("shows no failure banner when the workspace genuinely has zero targets", async () => {
    resolveDecorativeFacets();
    targets.mockResolvedValue([]);

    render(<ReportsPage />);

    await waitFor(() => expect(targets).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("offers a retry that re-issues the targets request rather than a full page reload", async () => {
    resolveDecorativeFacets();
    targets.mockRejectedValueOnce(new Error("network error"));
    targets.mockResolvedValueOnce([{ id: 1, name: "acme/repo", default_branch: "main" }]);

    render(<ReportsPage />);
    await screen.findByRole("alert");

    fireEvent.click(screen.getByRole("button", { name: /Retry/i }));

    await waitFor(() => expect(targets).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });
});
