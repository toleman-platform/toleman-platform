import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToolMarketplace } from "./tool-marketplace";
import type { ToolRegistryEntry } from "@/lib/api";

/**
 * admin M1/M2: the marketplace's per-tool badge used to have only two
 * rendered states (green "healthy" / red "everything else") for what are
 * really three conditions once a bundled tool is in the mix: a confirmed
 * healthy tool, a confirmed problem (broken, or a genuinely non-bundled
 * tool nobody has installed), and a bundled tool reading "not installed"
 * with no install button and no worker-side record to check against --
 * a probe that settled nothing, not a confident negative. These tests are
 * about that third state specifically; they are not a full re-test of the
 * marketplace page.
 */
const { workspaces, toolsRegistry, toolAssignments, activeToolInstalls } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  toolsRegistry: vi.fn(),
  toolAssignments: vi.fn(),
  activeToolInstalls: vi.fn(() => Promise.resolve({})),
}));

// Spread the real module rather than enumerating its exports: this file holds
// two suites (health badges and the workspace picker) that need different
// parts of @/lib/api, and a hand-listed mock silently drops whatever the other
// suite depends on -- `workspaceDisplayName` is a pure helper the picker
// asserts the real behaviour of, not something worth stubbing.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      workspaces,
      toolsRegistry,
      toolAssignments,
      activeToolInstalls,
      installTool: vi.fn(),
      getToolInstall: vi.fn(),
      saveToolAssignment: vi.fn(),
    },
  };
});

afterEach(() => {
  workspaces.mockReset();
  toolsRegistry.mockReset();
  toolAssignments.mockReset();
  activeToolInstalls.mockReset();
  activeToolInstalls.mockResolvedValue({});
});

function entry(overrides: Partial<ToolRegistryEntry> = {}): ToolRegistryEntry {
  return {
    tool: "semgrep",
    display_name: "Semgrep",
    category: "SAST",
    languages: ["python"],
    description: "Static analysis.",
    install_cmd: "pip install semgrep",
    docs_url: "https://semgrep.dev/docs/",
    integrated: true,
    installed: true,
    version: "1.0.0",
    response_ms: 12,
    checked_in: "api",
    installable: true,
    bundled: true,
    ...overrides,
  };
}

async function renderMarketplace(entries: ToolRegistryEntry[]) {
  workspaces.mockResolvedValue([{ id: 1, name: "default", organization_id: 1, enforcement_mode: null }]);
  toolsRegistry.mockResolvedValue(entries);
  toolAssignments.mockResolvedValue([]);
  render(<ToolMarketplace />);
  // Wait for the registry fetch to resolve and the grouped cards to render.
  await screen.findByText(entries[0].display_name);
}

// Every mocked call gets a usable default before each test, so a suite only
// has to prime what it actually asserts. Without this, a test that cares only
// about the workspace picker still crashes on `.then` of an unprimed
// toolsRegistry -- which is exactly how two independently-written suites
// behave once they share one mock.
beforeEach(() => {
  workspaces.mockResolvedValue([]);
  toolsRegistry.mockResolvedValue([]);
  toolAssignments.mockResolvedValue([]);
  activeToolInstalls.mockResolvedValue({});
});

describe("ToolMarketplace install/health badge", () => {
  it("shows healthy for an installed tool with a reported version", async () => {
    await renderMarketplace([entry({ tool: "semgrep", installed: true, version: "1.136.0" })]);
    expect(await screen.findByText("healthy")).toBeDefined();
  });

  it("shows a confident 'not installed' for a non-bundled tool nobody has installed", async () => {
    await renderMarketplace([
      entry({ tool: "checkov", display_name: "Checkov", bundled: false, installed: false, version: null }),
    ]);
    const label = await screen.findByText("not installed");
    // The label text itself is a bare inner <span>; StatusBadge's status
    // styling lives on its parent (see status-badge.test.tsx's own
    // "querySelector('span')" -- that first, outer span).
    expect(label.parentElement?.className).toContain("destructive");
  });

  it("shows a confident 'error', not 'unverified', for a bundled tool that is present but broken", async () => {
    // installed:true, version:null -- shutil.which found the binary, the
    // --version subprocess is what failed. Bundled-ness doesn't make this
    // any less of a real, confirmed problem.
    await renderMarketplace([
      entry({ tool: "gitleaks", display_name: "Gitleaks", bundled: true, installable: false, installed: true, version: null }),
    ]);
    const label = await screen.findByText("error");
    expect(label.parentElement?.className).toContain("destructive");
    expect(screen.queryByText("unverified")).toBeNull();
  });

  it("shows 'unverified', not a confident 'not installed', for a bundled tool this probe can't see", async () => {
    // The actual bug: bundled tools ship in the same image the worker
    // uses and get no worker-health record (that is only ever written by
    // a completed one-click install), so a negative reading here is not
    // the same claim as "go install this" -- there is nothing to confirm
    // it against.
    await renderMarketplace([
      entry({ tool: "gosec", display_name: "gosec", bundled: true, installable: false, installed: false, version: null }),
    ]);
    const label = await screen.findByText("unverified");
    // Distinct from the destructive "not installed"/"error" styling --
    // otherwise this is the exact same two-states-for-three-conditions bug
    // with a different label.
    expect(label.parentElement?.className).not.toContain("destructive");
    expect(screen.queryByText("not installed")).toBeNull();
  });

  it("still shows healthy for a bundled, pip-installable tool that reports installed", async () => {
    // semgrep and modelscan are both bundled and pip_package'd; the
    // 'unverified' branch must never shadow a genuinely healthy report.
    await renderMarketplace([
      entry({ tool: "modelscan", display_name: "ModelScan", bundled: true, installable: true, installed: true, version: "0.8.4" }),
    ]);
    expect(await screen.findByText("healthy")).toBeDefined();
    expect(screen.queryByText("unverified")).toBeNull();
  });
});


describe("ToolMarketplace workspace picker", () => {
  it("disambiguates two workspaces that share a name", async () => {
    workspaces.mockResolvedValue([
      { id: 1, name: "default", organization_id: 1, enforcement_mode: null },
      { id: 2, name: "default", organization_id: 2, enforcement_mode: null },
    ]);
    render(<ToolMarketplace />);

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
    render(<ToolMarketplace />);

    expect(await screen.findByRole("option", { name: "production" })).toBeDefined();
    expect(screen.getByRole("option", { name: "staging" })).toBeDefined();
  });
});
