import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { FpRules } from "./fp-rules";
import { renderWithWorkspace } from "@/test/render-with-workspace";

/**
 * The rule list's empty state used to be reached by `!rules || rules.length
 * === 0`, which is true both of a workspace that has learned no rules and of a
 * request that never came back. On this surface those are opposite facts: "no
 * false-positive rules learned yet" says nothing in this workspace is being
 * auto-suppressed, so every finding a scan produces is reaching the queue. A
 * failed read says only that we do not know, and a rule could be quietly
 * swallowing findings an operator is about to conclude do not exist.
 */
const { workspaces, fpRules, fpRuleStats, setFpRuleActive, widenFpRule, deleteFpRule } = vi.hoisted(() => ({
  workspaces: vi.fn(),
  fpRules: vi.fn(),
  fpRuleStats: vi.fn(),
  setFpRuleActive: vi.fn(),
  widenFpRule: vi.fn(),
  deleteFpRule: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { workspaces, fpRules, fpRuleStats, setFpRuleActive, widenFpRule, deleteFpRule },
  // The single-workspace fixture below never collides on name, so the real
  // disambiguation helper is not what these tests are about.
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

afterEach(() => {
  workspaces.mockReset();
  fpRules.mockReset();
  fpRuleStats.mockReset();
  setFpRuleActive.mockReset();
  widenFpRule.mockReset();
  deleteFpRule.mockReset();
});

function fpRule(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: 4,
    workspace_id: 1,
    rule_id: "python.lang.security.audit.exec-detected",
    tool: "semgrep",
    file_path_pattern: "tasks.py",
    source_finding_id: 91,
    created_by: "sec@example.com",
    created_at: "2026-01-01T00:00:00Z",
    active: true,
    match_count: 3,
    last_matched_at: "2026-02-01T00:00:00Z",
    ...over,
  };
}

function withWorkspace() {
  workspaces.mockResolvedValue([{ id: 1, name: "Acme", organization_id: 1, enforcement_mode: null }]);
  fpRuleStats.mockResolvedValue({ active_rules: 0, total_matches: 0 });
}

describe("FpRules, a read that failed vs a workspace with no learned rules", () => {
  it("reports the failure rather than claiming nothing is being auto-suppressed", async () => {
    withWorkspace();
    fpRules.mockRejectedValue(new Error("fp-rules endpoint unavailable"));

    renderWithWorkspace(<FpRules />);

    expect(await screen.findByText("Couldn't load false-positive rules")).toBeTruthy();
    expect(screen.queryByText("No false-positive rules learned yet")).toBeNull();
  });

  it("states the reason once, not twice", async () => {
    // The inline error line and the ErrorState description were both fed from
    // the same load error. getByText throws on a second match, so this fails
    // if the sentence is printed in both places.
    withWorkspace();
    fpRules.mockRejectedValue(new Error("fp-rules endpoint unavailable"));

    renderWithWorkspace(<FpRules />);

    await screen.findByText("Couldn't load false-positive rules");
    expect(screen.getByText("fp-rules endpoint unavailable")).toBeTruthy();
  });

  it("offers a retry that re-runs the read and shows the rules it returns", async () => {
    withWorkspace();
    fpRules
      .mockRejectedValueOnce(new Error("fp-rules endpoint unavailable"))
      .mockResolvedValue([fpRule()]);

    renderWithWorkspace(<FpRules />);
    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));

    expect(await screen.findByText("python.lang.security.audit.exec-detected")).toBeTruthy();
    expect(screen.queryByText("Couldn't load false-positive rules")).toBeNull();
    expect(screen.queryByText("No false-positive rules learned yet")).toBeNull();
  });

  it("still says none have been learned when the read succeeds and returns none", async () => {
    // The other half of the pair: gating the empty state on a successful read
    // must not silence it for the workspace that genuinely has no rules.
    withWorkspace();
    fpRules.mockResolvedValue([]);

    renderWithWorkspace(<FpRules />);

    expect(await screen.findByText("No false-positive rules learned yet")).toBeTruthy();
    expect(screen.queryByText("Couldn't load false-positive rules")).toBeNull();
  });
});
