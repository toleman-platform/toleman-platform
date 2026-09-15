import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { TargetsList } from "./targets-list";
import type { Target } from "@/lib/api";

/**
 * This page used to hand-roll its own selection bar: a "{n} selected" span, a
 * primary button, and a lowercase "clear selection" link, inside a static
 * bordered div. Every other list (Findings, Scans, API Discovery) used
 * `BulkActionBar`, so the wording ("3 selected" vs "3 findings selected"),
 * the Escape-to-clear shortcut and the `role="status"` announcement were all
 * page-dependent. These tests pin the converged behaviour, and the one thing
 * converging gets wrong if it is done carelessly: `BulkActionBar` renders
 * null at zero selected, so Mass Rollout -- the action whose entire purpose
 * is rolling out without ticking anything -- must stay outside it.
 */
const { workspaces, groups, pipelineTemplates, bulkPipelineIntegrate, massPipelineRollout } = vi.hoisted(() => ({
  workspaces: vi.fn().mockResolvedValue([]),
  groups: vi.fn().mockResolvedValue([]),
  pipelineTemplates: vi.fn().mockResolvedValue([]),
  bulkPipelineIntegrate: vi.fn(),
  massPipelineRollout: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, workspaces, groups, pipelineTemplates, bulkPipelineIntegrate, massPipelineRollout },
  };
});

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/targets",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

// The real hook opens a polling loop against /api/scans/active on mount. No
// scan is in flight in any of these tests, and a live timer would only add
// `role="status"` progress nodes for the bar assertions to trip over.
vi.mock("@/hooks/features/use-active-scans", () => ({
  useActiveScans: () => ({ activeScans: {}, isTargetScanning: () => false, refresh: vi.fn() }),
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
    pipeline_integrated: false,
    pipeline_pr_url: null,
    is_ai_repo: false,
    is_ai_repo_signals: "",
    is_ai_repo_override: null,
    is_ai_repo_effective: false,
    enforcement_mode: null,
    api_base_url: null,
    diff_scoped_pr_scans: false,
    dependency_sync_status: null,
    dependency_sync_error: null,
    dependency_sync_at: null,
    dependency_component_count: null,
    is_active: true,
    deactivated_at: null,
    deleted_at: null,
    ...over,
  } as Target;
}

function renderList() {
  return render(
    <TargetsList targets={[target({ id: 1, name: "alpha" }), target({ id: 2, name: "beta" })]} />,
  );
}

describe("TargetsList bulk selection", () => {
  it("shows no selection bar at zero selected, and keeps Mass Rollout reachable there", () => {
    renderList();

    expect(screen.queryByRole("status")).toBeNull();
    // The bar is where the batch action lives, so it is gone too...
    expect(screen.queryByRole("button", { name: /Add Pipeline/ })).toBeNull();
    // ...while the scope-based rollout, which needs no selection at all, is
    // still on the page. This is the regression the convergence can cause.
    expect(screen.getByRole("button", { name: /Mass Rollout/ })).toBeTruthy();
  });

  it("announces the count with the shared wording and pluralises the noun", () => {
    renderList();

    fireEvent.click(screen.getByLabelText("Select alpha"));
    // Read as a fresh string at each step: React reuses the DOM node across
    // re-renders, so a retained element reference would report the new text
    // and any "changed" assertion against it would compare a string to
    // itself.
    const afterOne = screen.getByRole("status").textContent ?? "";
    expect(afterOne.includes("1 target selected")).toBe(true);
    expect(afterOne.includes("1 targets selected")).toBe(false);

    fireEvent.click(screen.getByLabelText("Select beta"));
    const afterTwo = screen.getByRole("status").textContent ?? "";
    expect(afterTwo.includes("2 targets selected")).toBe(true);
    expect(afterTwo).not.toBe(afterOne);
  });

  it("marks the bar as a polite live region", () => {
    renderList();
    fireEvent.click(screen.getByLabelText("Select alpha"));

    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
  });

  it("keeps the batch action label in step with the selection", () => {
    renderList();

    fireEvent.click(screen.getByLabelText("Select alpha"));
    expect(screen.getByRole("button", { name: "Add Pipeline to 1 repo" })).toBeTruthy();

    fireEvent.click(screen.getByLabelText("Select beta"));
    expect(screen.getByRole("button", { name: "Add Pipeline to 2 repos" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Add Pipeline to 1 repo" })).toBeNull();
  });

  it("leaves Mass Rollout available while a selection is live", () => {
    renderList();
    fireEvent.click(screen.getByLabelText("Select alpha"));

    expect(screen.getByRole("status")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Mass Rollout/ })).toBeTruthy();
  });

  it("clears the selection from the bar's own Clear control", () => {
    renderList();
    fireEvent.click(screen.getByLabelText("Select alpha"));

    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));

    expect(screen.queryByRole("status")).toBeNull();
    expect((screen.getByLabelText("Select alpha") as HTMLInputElement).checked).toBe(false);
  });

  it("clears the selection on Escape, which the page-local bar never did", () => {
    renderList();
    fireEvent.click(screen.getByLabelText("Select alpha"));
    expect(screen.getByRole("status")).toBeTruthy();

    fireEvent.keyDown(window, { key: "Escape" });

    expect(screen.queryByRole("status")).toBeNull();
  });

  it("ticks every visible row from the shared select-all control", () => {
    renderList();

    fireEvent.click(screen.getByLabelText(/Select all on this page/));

    const afterAll = screen.getByRole("status").textContent ?? "";
    expect(afterAll.includes("2 targets selected")).toBe(true);
    expect((screen.getByLabelText("Select alpha") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("Select beta") as HTMLInputElement).checked).toBe(true);
  });

  it("puts the select-all box in the indeterminate state on a part-selected page", () => {
    renderList();
    const selectAll = () => screen.getByLabelText(/Select all on this page/) as HTMLInputElement;

    expect(selectAll().indeterminate).toBe(false);

    fireEvent.click(screen.getByLabelText("Select alpha"));
    expect(selectAll().indeterminate).toBe(true);
    expect(selectAll().checked).toBe(false);

    fireEvent.click(screen.getByLabelText("Select beta"));
    expect(selectAll().indeterminate).toBe(false);
    expect(selectAll().checked).toBe(true);
  });
});
