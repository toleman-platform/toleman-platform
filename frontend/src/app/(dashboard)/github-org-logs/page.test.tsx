import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import GithubOrgLogsPage from "./page";

/**
 * The repository filter used to be fed by `api.targets().catch(() => [])`. An
 * org with no connected repositories and an org whose repository list failed
 * to load then rendered the same thing: a filter offering nothing but "All
 * repositories", on the page whose own header claims to show activity from
 * every repository you have connected (AGENTS.md 1.4).
 */

const { orgActivity, targets } = vi.hoisted(() => ({
  orgActivity: vi.fn(),
  targets: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ api: { orgActivity, targets } }));

// The filter bar, the date range filter and the pagination all read the URL
// through these; a plain component render has no App Router above it.
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/github-org-logs",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

afterEach(() => {
  orgActivity.mockReset();
  targets.mockReset();
});

// An async Server Component: calling it returns a promise of the tree, so it
// has to be awaited before Testing Library ever sees it.
async function renderPage() {
  const element = await GithubOrgLogsPage({ searchParams: Promise.resolve({}) });
  render(element);
}

describe("GitHub Org Logs, when the repository list can't be loaded", () => {
  it("says the filter is short rather than presenting it as an org with no repos", async () => {
    orgActivity.mockResolvedValue({ items: [], total: 0 });
    targets.mockRejectedValue(new Error("targets service unavailable"));

    await renderPage();

    expect(screen.getByText("Repository list")).toBeTruthy();
    expect(screen.getByText(/so filtering by repository is unavailable/)).toBeTruthy();
  });

  it("still renders the activity feed it did manage to load", async () => {
    orgActivity.mockResolvedValue({ items: [], total: 0 });
    targets.mockRejectedValue(new Error("targets service unavailable"));

    await renderPage();

    // A failed secondary read degrades the page; it does not replace it.
    expect(screen.getByLabelText("Filter by repository")).toBeTruthy();
    expect(screen.getByText("No activity found")).toBeTruthy();
  });

  it("says nothing at all when the repository list loaded", async () => {
    orgActivity.mockResolvedValue({ items: [], total: 0 });
    targets.mockResolvedValue([{ id: 4, name: "acme/api" }]);

    await renderPage();

    expect(screen.queryByText("Repository list")).toBeNull();
    expect(screen.getByRole("option", { name: "acme/api" })).toBeTruthy();
  });
});

describe("GitHub Org Logs, when the activity feed can't be loaded", () => {
  it("reports the failure instead of an empty feed", async () => {
    orgActivity.mockRejectedValue(new Error("upstream down"));
    targets.mockResolvedValue([{ id: 4, name: "acme/api" }]);

    await renderPage();

    expect(screen.getByText("GitHub org activity couldn't be loaded from the API.")).toBeTruthy();
    // "No activity found" would be a claim about the org, not about the read.
    expect(screen.queryByText("No activity found")).toBeNull();
  });
});
