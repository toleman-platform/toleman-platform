import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { PrGuardrailLog } from "./pr-guardrail-log";
import type { PrGuardrailLogEntry } from "@/lib/api";

// The log fetches its own rows; only that boundary is mocked, so the scope
// line under test is the real one the page renders.
const { getPrGuardrailLog } = vi.hoisted(() => ({ getPrGuardrailLog: vi.fn() }));

vi.mock("@/lib/api", () => ({
  api: { getPrGuardrailLog, getPrGuardrailOrgLog: vi.fn() },
  LOG_STATUS_COLOR: {},
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

function scan(overrides: Partial<PrGuardrailLogEntry> = {}): PrGuardrailLogEntry {
  return {
    id: 1,
    pr_number: 7,
    pr_title: "a pr",
    branch: "feature",
    status: "passed",
    new_findings_count: 0,
    highest_new_severity: null,
    new_endpoints_count: 0,
    tools_run: ["semgrep"],
    tools_failed: [],
    created_at: "2026-09-01T00:00:00Z",
    completed_at: "2026-09-01T00:01:00Z",
    ...overrides,
  } as PrGuardrailLogEntry;
}

async function renderLog(entry: PrGuardrailLogEntry) {
  getPrGuardrailLog.mockResolvedValue([entry]);
  render(<PrGuardrailLog targetId={1} />);
  return screen.findByText(/Diff-scoped|Full scan:/);
}

describe("PR Guardrail log scope line", () => {
  it("splits changed files from the ones the import graph pulled in", async () => {
    // (#244) "12 changed file(s) only" would be a false description of a scan
    // that deliberately reached past the diff, and understates its coverage.
    const line = await renderLog(
      scan({ scan_scope: "diff", files_scanned: 12, blast_radius_files: 10 }),
    );

    expect(line.textContent).toContain("the 2 changed in this PR plus 10 that import them");
    expect(line.textContent).toContain("not the full repo");
  });

  it("keeps the plain wording when the radius really was just the diff", async () => {
    const line = await renderLog(
      scan({ scan_scope: "diff", files_scanned: 4, blast_radius_files: 0 }),
    );

    expect(line.textContent).toContain("4 changed file(s) only");
    expect(line.textContent).not.toContain("import them");
  });

  it("says why a scan that meant to be diff-scoped ran in full", async () => {
    // Without this, an escalated full scan is indistinguishable from a target
    // that never opted into diff scoping at all.
    const line = await renderLog(
      scan({ scan_scope: "full", scope_reason: "the PR's changed-file list could not be retrieved" }),
    );

    expect(line.textContent).toContain("could not be retrieved");
  });
});
