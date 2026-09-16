import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import SbomPage from "./page";
import type { SbomComponent, Target } from "@/lib/api";
import { renderWithWorkspace } from "@/test/render-with-workspace";

/**
 * The Components tab rendered 717 components as one large card each, with the
 * purl occupying the whole right-hand column. It is now the shared
 * PaginatedList shell over ListRow; these tests pin the part that must not
 * change with the layout -- every field that was on screen is still on
 * screen, and the "New" badge still only appears after a scan run in this
 * session, because a plain GET always reports is_new: false.
 */
const { targets, getSbom, findingGroups, workspaces } = vi.hoisted(() => ({
  targets: vi.fn(),
  getSbom: vi.fn(),
  findingGroups: vi.fn(),
  workspaces: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, targets, getSbom, findingGroups, workspaces } };
});

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/sbom",
  useSearchParams: () => new URLSearchParams(),
}));

function target(over: Partial<Target> = {}): Target {
  return {
    id: 1,
    workspace_id: 1,
    name: "svc",
    repo_url: "https://github.com/acme/svc",
    default_branch: "main",
    label: "Internal",
    criticality_weight: 2,
    groups: [],
    is_active: true,
    ...over,
  } as Target;
}

let nextId = 1;
function component(over: Partial<SbomComponent> = {}): SbomComponent {
  return {
    id: nextId++,
    name: "lodash",
    version: "4.17.21",
    package_type: "npm",
    purl: "pkg:npm/lodash@4.17.21",
    source: "github",
    is_new: false,
    first_seen: "2024-03-05T00:00:00Z",
    last_seen: "2024-03-05T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  nextId = 1;
  targets.mockReset();
  getSbom.mockReset();
  findingGroups.mockReset();
  workspaces.mockReset();
  targets.mockResolvedValue([target()]);
  findingGroups.mockResolvedValue({ items: [], total: 0, total_findings: 0, truncated: false });
  workspaces.mockResolvedValue([]);
});

describe("SBOM components tab", () => {
  it("still shows every field the card layout showed", async () => {
    getSbom.mockResolvedValue({
      target_id: 1,
      count: 2,
      components: [
        component(),
        component({ name: "requests", version: "2.31.0", package_type: "pypi", purl: "pkg:pypi/requests@2.31.0" }),
      ],
    });

    renderWithWorkspace(<SbomPage />);

    expect(await screen.findByText("2 components")).not.toBeNull();
    // Name, version, ecosystem, purl and the first-seen date, one component
    // per assertion set so a dropped field cannot hide behind its neighbour.
    expect(screen.getByText("lodash")).not.toBeNull();
    expect(screen.getByText("4.17.21")).not.toBeNull();
    expect(screen.getByText("npm")).not.toBeNull();
    expect(screen.getByText("pkg:npm/lodash@4.17.21")).not.toBeNull();
    expect(screen.getByText("requests")).not.toBeNull();
    expect(screen.getByText("2.31.0")).not.toBeNull();
    expect(screen.getByText("pypi")).not.toBeNull();
    expect(screen.getByText("pkg:pypi/requests@2.31.0")).not.toBeNull();
    expect(screen.getAllByText("since Mar 5").length).toBe(2);
  });

  it("keeps the full purl available even though the column is capped", async () => {
    getSbom.mockResolvedValue({ target_id: 1, count: 1, components: [component()] });

    renderWithWorkspace(<SbomPage />);

    const purl = await screen.findByText("pkg:npm/lodash@4.17.21");
    // Truncation is what stops the longest and least discriminating string in
    // the row from taking the width; the whole value has to stay reachable.
    expect(purl.className).toContain("truncate");
    expect(purl.getAttribute("title")).toBe("pkg:npm/lodash@4.17.21");
  });

  it("shows the component's recorded source", async () => {
    getSbom.mockResolvedValue({
      target_id: 1,
      count: 1,
      components: [component({ source: "github,upload" })],
    });

    renderWithWorkspace(<SbomPage />);

    expect(await screen.findByText("github,upload")).not.toBeNull();
  });

  it("says nothing about provenance when the row does not carry it", async () => {
    // An older row has no recorded source. A blank slot is the honest
    // rendering; inventing "github" would be a claim the data does not make.
    getSbom.mockResolvedValue({
      target_id: 1,
      count: 1,
      components: [component({ source: undefined })],
    });

    renderWithWorkspace(<SbomPage />);

    await screen.findByText("lodash");
    expect(screen.queryByText("github")).toBeNull();
  });

  it("cancels the base Card padding so the rows are actually dense", async () => {
    // The base Card's py-6 is 48px no density token can reach; ListRow's
    // py-0 is the whole reason the rows collapse.
    getSbom.mockResolvedValue({ target_id: 1, count: 1, components: [component()] });

    renderWithWorkspace(<SbomPage />);

    const row = (await screen.findByText("lodash")).closest("[data-slot='card']") as HTMLElement;
    expect(row).not.toBeNull();
    expect(row.className).toContain("py-0");
  });

  it("pages the inventory instead of rendering all of it", async () => {
    getSbom.mockResolvedValue({
      target_id: 1,
      count: 30,
      components: Array.from({ length: 30 }, (_, i) =>
        component({ name: `pkg-${i + 1}`, purl: `pkg:npm/pkg-${i + 1}@1.0.0` }),
      ),
    });

    renderWithWorkspace(<SbomPage />);

    expect(await screen.findByText("30 components")).not.toBeNull();
    expect(screen.getByText("pkg-25")).not.toBeNull();
    // The default page is 25 rows; the 26th must be behind the pager.
    expect(screen.queryByText("pkg-26")).toBeNull();
    expect(screen.getAllByRole("button", { name: "Next" }).length).toBeGreaterThan(0);
  });

  it("does not badge components as new on a plain load", async () => {
    // GET /api/sbom always reports is_new: false for a fresh read; the badge
    // is only meaningful next to a run that happened in this session.
    getSbom.mockResolvedValue({
      target_id: 1,
      count: 1,
      components: [component({ is_new: true })],
    });

    renderWithWorkspace(<SbomPage />);

    await screen.findByText("lodash");
    expect(screen.queryByText("New")).toBeNull();
  });

  it("offers the empty state, not a list, when nothing has been recorded", async () => {
    getSbom.mockResolvedValue({ target_id: 1, count: 0, components: [] });

    renderWithWorkspace(<SbomPage />);

    expect(await screen.findByText("No components recorded yet")).not.toBeNull();
    expect(screen.getByText("0 components")).not.toBeNull();
  });
});
