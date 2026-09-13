import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PrGuardrailLog, groupFindings } from "@/components/features/scans";
import type { PrGuardrailFinding, PrGuardrailLogEntry } from "@/lib/api";

// (#383) One hardcoded key on one line, flagged by semgrep and gitleaks
// independently. Both findings are real and both stay independently
// ignorable; what changes is that they read as one problem to fix instead of
// two. The grouping itself is decided server-side -- these rows carry exactly
// what GET /api/pr-guardrail/{id}/findings sends.

const { getPrGuardrailLog, getPrGuardrailFindings, requestIgnoreFinding } = vi.hoisted(() => ({
  getPrGuardrailLog: vi.fn(),
  getPrGuardrailFindings: vi.fn(),
  requestIgnoreFinding: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { getPrGuardrailLog, getPrGuardrailOrgLog: vi.fn(), getPrGuardrailFindings, requestIgnoreFinding },
  ApiError: class ApiError extends Error {},
  LOG_STATUS_COLOR: {},
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

function finding(overrides: Partial<PrGuardrailFinding> = {}): PrGuardrailFinding {
  return {
    id: 1,
    pr_scan_id: 1,
    tool: "semgrep",
    rule_id: "generic.secrets.security.detected-aws-access-key-id-value",
    title: "Detected AWS access key ID",
    file_path: "README.md",
    line_start: 7,
    severity: "High",
    ignore_status: "none",
    ignore_requested_by: "",
    ignore_requested_reason: "",
    ignore_reviewed_by: "",
    ignore_reviewed_at: null,
    group_key: "README.md:7",
    group_size: 2,
    group_tools: ["semgrep", "gitleaks"],
    group_severity: "High",
    group_primary_id: 1,
    ...overrides,
  };
}

const GITLEAKS = finding({
  id: 2,
  tool: "gitleaks",
  rule_id: "aws-access-token",
  title: "AWS access token",
});

function scan(overrides: Partial<PrGuardrailLogEntry> = {}): PrGuardrailLogEntry {
  return {
    id: 1,
    pr_number: 3,
    pr_title: "add a readme",
    branch: "feature",
    status: "blocked",
    new_findings_count: 2,
    highest_new_severity: "High",
    new_endpoints_count: 0,
    tools_run: ["semgrep", "gitleaks"],
    tools_failed: [],
    created_at: "2026-09-01T00:00:00Z",
    completed_at: "2026-09-01T00:01:00Z",
    ...overrides,
  } as PrGuardrailLogEntry;
}

// The log card starts expanded via initialScanId, which is also how a PR
// comment's "view" link lands here -- otherwise the findings never render.
async function renderFindings(findings: PrGuardrailFinding[], initialIgnoreFindingId: number | null = null) {
  getPrGuardrailLog.mockResolvedValue([scan()]);
  getPrGuardrailFindings.mockResolvedValue(findings);
  render(
    <PrGuardrailLog targetId={1} initialScanId={1} initialIgnoreFindingId={initialIgnoreFindingId} />,
  );
  // findAll: a collapsed group renders both its title and its "found by"
  // line, and this only has to wait for the list to arrive.
  await screen.findAllByText(/found by:|Detected AWS access key ID/);
}

describe("groupFindings", () => {
  it("buckets rows the backend put in one group", () => {
    const groups = groupFindings([finding(), GITLEAKS]);

    expect(groups).toHaveLength(1);
    expect(groups[0].tools).toEqual(["semgrep", "gitleaks"]);
    expect(groups[0].findings.map((f) => f.id)).toEqual([1, 2]);
  });

  it("keeps different locations apart", () => {
    const groups = groupFindings([
      finding(),
      finding({ id: 2, tool: "gitleaks", group_key: "README.md:9", group_size: 1, group_tools: ["gitleaks"] }),
    ]);

    expect(groups).toHaveLength(2);
  });

  it("takes the group's severity and primary from the backend, not from row order", () => {
    // Tools disagree about the same line all the time; the collapsed row has
    // to read at the highest severity present, whichever row arrived first.
    const groups = groupFindings([
      finding({ severity: "Medium", group_severity: "Critical", group_primary_id: 2 }),
      finding({ id: 2, tool: "gitleaks", title: "AWS access token", severity: "Critical", group_severity: "Critical", group_primary_id: 2 }),
    ]);

    expect(groups[0].severity).toBe("Critical");
    expect(groups[0].primary.id).toBe(2);
  });

  it("degrades to one group per finding when the response carries no grouping", () => {
    const flat = [
      { ...finding(), group_key: undefined, group_size: undefined, group_tools: undefined },
      { ...GITLEAKS, group_key: undefined, group_size: undefined, group_tools: undefined },
    ];

    expect(groupFindings(flat)).toHaveLength(2);
  });
});

describe("PR Guardrail findings list", () => {
  it("collapses one line flagged by two tools into a single row naming both", async () => {
    await renderFindings([finding(), GITLEAKS]);

    expect(screen.getByText(/found by: semgrep, gitleaks/)).toBeTruthy();
    // Collapsed: each tool's own rule is a click away, not a second top-level row.
    expect(screen.queryByText(/aws-access-token/)).toBeNull();
    expect(screen.getByText(/2 detections, grouped into 1 by location/)).toBeTruthy();
  });

  it("shows each tool's own rule and its own ignore action on expand", async () => {
    await renderFindings([finding(), GITLEAKS]);

    await userEvent.click(screen.getByText(/Show 2 findings/));

    expect(screen.getByText(/aws-access-token/)).toBeTruthy();
    expect(screen.getByText(/generic.secrets.security.detected-aws-access-key-id-value/)).toBeTruthy();
    // One Request Ignore per member: grouping is presentation, approvals stay
    // per-finding.
    expect(screen.getAllByText("Request Ignore")).toHaveLength(2);
  });

  it("leaves an ungrouped finding as a plain row", async () => {
    await renderFindings([
      finding({ group_key: "README.md:7", group_size: 1, group_tools: ["semgrep"] }),
    ]);

    expect(screen.queryByText(/found by:/)).toBeNull();
    expect(screen.queryByText(/grouped into/)).toBeNull();
    expect(screen.getByText(/Detected AWS access key ID/)).toBeTruthy();
  });

  it("opens the group holding a deep-linked finding so its one-click ignore still fires", async () => {
    // A PR comment's "request ignore" link fires from the finding row's own
    // mount effect (#385/#393). Inside a collapsed group that click would
    // otherwise do nothing at all.
    requestIgnoreFinding.mockResolvedValue(GITLEAKS);
    await renderFindings([finding(), GITLEAKS], 2);

    expect(await screen.findByText(/aws-access-token/)).toBeTruthy();
    expect(requestIgnoreFinding).toHaveBeenCalledWith(2, expect.any(String));
  });
});
