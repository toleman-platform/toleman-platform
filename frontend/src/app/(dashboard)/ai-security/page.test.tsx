import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import AiSecurityPage from "./page";
import type { Target } from "@/lib/api";

/**
 * This page used to be the one dashboard surface with no destination on it:
 * three counters that did not link anywhere, a repo list with no actions,
 * and a section that plainly said a feature did not exist. These tests pin
 * the three things that changed --
 *
 *   1. every counter and badge is a real link, and the finding counters
 *      link to the exact query the count was computed from (never/scanned
 *      distinction included, per AGENTS.md #4);
 *   2. the AI Bill of Materials section generates and exports in place;
 *   3. the "not yet available" dead section is gone.
 */
const { targetsFn, scanSummaryFn, findingsFn, generateSbomFn, getSbomRunFn, aibomFn } = vi.hoisted(() => ({
  targetsFn: vi.fn(),
  scanSummaryFn: vi.fn(),
  findingsFn: vi.fn(),
  generateSbomFn: vi.fn(),
  getSbomRunFn: vi.fn(),
  aibomFn: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: {
    targets: targetsFn,
    scanSummary: scanSummaryFn,
    findings: findingsFn,
    generateSbom: generateSbomFn,
    getSbomRun: getSbomRunFn,
    aibom: aibomFn,
  },
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
    is_ai_repo: true,
    is_ai_repo_signals: "pytorch in requirements.txt",
    is_ai_repo_override: null,
    is_ai_repo_effective: true,
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

function finding(targetId: number) {
  return { id: Math.random(), target_id: targetId, tool: "modelscan" };
}

// Default: no findings for either AI tool, empty scan history. Individual
// tests override whichever of these the case under test needs.
beforeEach(() => {
  targetsFn.mockReset();
  scanSummaryFn.mockReset();
  findingsFn.mockReset();
  generateSbomFn.mockReset();
  getSbomRunFn.mockReset();
  aibomFn.mockReset();

  scanSummaryFn.mockResolvedValue({});
  findingsFn.mockResolvedValue({ items: [], total: 0 });
  aibomFn.mockResolvedValue({
    target_id: 1,
    target_name: "svc",
    branch: "main",
    generated: false,
    summary: { models: 0, datasets: 0, unpinned: 0, hosted_api_models: 0 },
    components: [],
  });
});

describe("AiSecurityPage - counters and repo destinations", () => {
  it("links the sole AI/ML repo counter straight to that target, not to a list", async () => {
    targetsFn.mockResolvedValue([target({ id: 7, name: "model-server" })]);

    render(<AiSecurityPage />);

    const repoCounterLabel = await screen.findByText("AI/ML repos");
    const link = repoCounterLabel.closest("a");
    expect(link).not.toBeNull();
    expect(link!.getAttribute("href")).toBe("/targets/7");
  });

  it("links the AI/ML repo counter to the on-page list when there is more than one", async () => {
    targetsFn.mockResolvedValue([
      target({ id: 7, name: "model-server" }),
      target({ id: 8, name: "chat-svc" }),
    ]);

    render(<AiSecurityPage />);

    const repoCounterLabel = await screen.findByText("AI/ML repos");
    const link = repoCounterLabel.closest("a");
    expect(link!.getAttribute("href")).toBe("#ai-flagged-repos");
  });

  it("links the ModelScan and LLM ruleset counters to Findings, pre-filtered and queue-matched to the count", async () => {
    targetsFn.mockResolvedValue([target({ id: 7 })]);

    render(<AiSecurityPage />);

    const modelscanLabel = await screen.findByText("ModelScan findings");
    expect(modelscanLabel.closest("a")!.getAttribute("href")).toBe("/findings?tool=modelscan&queue=all");

    const llmLabel = screen.getByText("LLM ruleset findings");
    expect(llmLabel.closest("a")!.getAttribute("href")).toBe("/findings?tool=semgrep-llm&queue=all");
  });

  it("does not render the removed 'not yet available' LLM red-teaming section", async () => {
    targetsFn.mockResolvedValue([target({ id: 7 })]);

    render(<AiSecurityPage />);
    await screen.findByText("AI/ML repos");

    expect(screen.queryByText("Not yet available")).toBeNull();
    expect(screen.queryByText(/red-teaming/i)).toBeNull();
    expect(screen.queryByText(/garak/i)).toBeNull();
  });
});

describe("AiSecurityPage - per-repo tool badge honesty (0 scanned-clean vs 0 never-scanned)", () => {
  it("renders a real finding count as an unambiguous, findings-linked badge", async () => {
    targetsFn.mockResolvedValue([target({ id: 7, name: "model-server" })]);
    findingsFn.mockImplementation((query: { tool: string }) =>
      Promise.resolve({
        items: query.tool === "modelscan" ? [finding(7), finding(7)] : [],
        total: query.tool === "modelscan" ? 2 : 0,
      }),
    );
    scanSummaryFn.mockResolvedValue({ "7": { last_scan_at: "2026-09-01T00:00:00Z", tools: ["modelscan"], suspect_tools: [] } });

    render(<AiSecurityPage />);

    const badge = await screen.findByText("2 ModelScan");
    expect(badge.closest("a")!.getAttribute("href")).toBe("/findings?tool=modelscan&target_id=7&queue=all");
  });

  it("renders a scanned-and-clean zero differently from a never-scanned zero, for the same tool", async () => {
    targetsFn.mockResolvedValue([
      target({ id: 7, name: "scanned-clean" }),
      target({ id: 8, name: "never-touched" }),
    ]);
    // Findings stay empty for both (default beforeEach mock); only scan
    // history differs: target 7 has actually run ModelScan, target 8 has
    // no row at all (never scanned by anything).
    scanSummaryFn.mockResolvedValue({
      "7": { last_scan_at: "2026-09-01T00:00:00Z", tools: ["modelscan", "semgrep-llm"], suspect_tools: [] },
    });

    render(<AiSecurityPage />);

    await screen.findByText("scanned-clean");
    // Scanned and found nothing: a real, measured zero.
    expect(screen.getByText("0 ModelScan")).toBeTruthy();
    // Never reached by the tool: must not read as a clean zero, and must not
    // print a bare "0" at all.
    const neverScanned = screen.getByText("ModelScan not scanned");
    expect(neverScanned.textContent).not.toContain("0");
  });

  it("shows an explicit unknown badge, not a clean zero, when scan history fails to load", async () => {
    targetsFn.mockResolvedValue([target({ id: 7, name: "model-server" })]);
    scanSummaryFn.mockRejectedValue(new Error("scan history down"));

    render(<AiSecurityPage />);

    const badge = await screen.findByText("ModelScan: unknown");
    expect(badge.getAttribute("title")).toMatch(/not known whether/i);
  });
});

describe("AiSecurityPage - aggregate counter honesty", () => {
  it("reads unknown, not a false zero, when no AI/ML repo has ever been scanned by a tool", async () => {
    targetsFn.mockResolvedValue([target({ id: 7 }), target({ id: 8 })]);
    scanSummaryFn.mockResolvedValue({}); // neither target has a row for any tool

    render(<AiSecurityPage />);

    await screen.findByText(/no AI\/ML repo has been scanned by ModelScan yet/);
  });

  it("notes partial coverage rather than implying every AI/ML repo was scanned", async () => {
    targetsFn.mockResolvedValue([target({ id: 7 }), target({ id: 8 })]);
    scanSummaryFn.mockResolvedValue({
      "7": { last_scan_at: "2026-09-01T00:00:00Z", tools: ["modelscan"], suspect_tools: [] },
      // target 8 has no row: never scanned by anything.
    });

    render(<AiSecurityPage />);

    await screen.findByText(/measured across 1 of 2 AI\/ML repos scanned/);
  });
});

describe("AiSecurityPage - AI Bill of Materials generates and exports in place", () => {
  // Real timers, deliberately: pollUntilSettled's first check fires after a
  // real 2s interval, and the suite's asyncUtilTimeout (src/test/setup.ts)
  // is raised to 5000ms specifically so a findByText can wait it out rather
  // than fighting fake-timer/microtask ordering for a single assertion.
  it("dispatches generation for the current target and refreshes the panel on completion", async () => {
    targetsFn.mockResolvedValue([target({ id: 7, name: "model-server" })]);
    generateSbomFn.mockResolvedValue({ run_id: 99, target_id: 7, status: "running" });
    getSbomRunFn.mockResolvedValue({
      run_id: 99,
      target_id: 7,
      status: "completed",
      count: 3,
      new_count: 3,
      error: "",
      started_at: "2026-09-15T00:00:00Z",
      completed_at: "2026-09-15T00:01:00Z",
    });
    // First mount reads "not generated yet"; the remount after generation
    // reads a populated AIBOM. Proves the panel actually refetches rather
    // than the button just spinning and going quiet.
    aibomFn
      .mockResolvedValueOnce({
        target_id: 7,
        target_name: "model-server",
        branch: "main",
        generated: false,
        summary: { models: 0, datasets: 0, unpinned: 0, hosted_api_models: 0 },
        components: [],
      })
      .mockResolvedValueOnce({
        target_id: 7,
        target_name: "model-server",
        branch: "main",
        generated: true,
        summary: { models: 1, datasets: 0, unpinned: 0, hosted_api_models: 0 },
        // Must line up with summary.models: 1 above -- AiBomPanel's isEmpty
        // check is `generated && components.length === 0`, so an empty
        // array here (despite summary.models: 1) makes the panel render its
        // "No models or datasets found" empty state instead of the
        // populated view this test is actually asserting on, which is what
        // was failing before this fix (not a timing issue: the text the
        // test waited for was never going to appear against this fixture).
        components: [
          {
            id: 1,
            name: "resnet50",
            component_type: "machine-learning-model",
            version: "1.0.0",
            source: "requirements.txt",
            evidence: "torchvision.models.resnet50",
            unpinned: false,
            first_seen: "2026-09-15T00:00:00Z",
            last_seen: "2026-09-15T00:00:00Z",
          },
        ],
      });

    render(<AiSecurityPage />);

    await screen.findByText("No AIBOM generated yet");

    fireEvent.click(screen.getByRole("button", { name: "Generate AI Bill of Materials" }));

    expect(await screen.findByText("Export CycloneDX 1.6")).toBeTruthy();
    expect(generateSbomFn).toHaveBeenCalledWith(7);
    expect(aibomFn).toHaveBeenCalledTimes(2);
  }, 10000);

  it("disables the export-in-place generate action for a deactivated target", async () => {
    targetsFn.mockResolvedValue([target({ id: 7, name: "frozen", is_active: false })]);

    render(<AiSecurityPage />);

    const button = await screen.findByRole("button", { name: "Generate AI Bill of Materials" });
    expect(button.hasAttribute("disabled")).toBe(true);
    expect(screen.getByText(/deactivated; scanning is off/)).toBeTruthy();
  });
});
