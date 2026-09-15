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
    reject_reason: null,
    ignore_status: "none",
    ignore_requested_by: "",
    ignore_requested_reason: "",
    ignore_reviewed_by: "",
    ignore_reviewed_at: null,
    // What the API actually sends: membership only. group_key is unique per
    // group (the backend appends the first member's id to the location), and
    // group_size is how many rows belong to it.
    group_key: "1@README.md:7",
    group_size: 2,
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
async function renderFindings(
  findings: PrGuardrailFinding[],
  initialIgnoreFindingId: number | null = null,
  settled: RegExp = /found by:|Detected AWS access key ID/,
) {
  getPrGuardrailLog.mockResolvedValue([scan()]);
  getPrGuardrailFindings.mockResolvedValue(findings);
  render(
    <PrGuardrailLog targetId={1} initialScanId={1} initialIgnoreFindingId={initialIgnoreFindingId} />,
  );
  // findAll: a collapsed group renders both its title and its "found by"
  // line, and this only has to wait for the list to arrive.
  await screen.findAllByText(settled);
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
      finding({ id: 2, tool: "gitleaks", group_key: "2@README.md:9", group_size: 1 }),
    ]);

    expect(groups).toHaveLength(2);
  });

  it("never merges rows the backend kept in groups of one", () => {
    // The shape that broke this: three trivy CVEs on one manifest, all with
    // no line number, are three separate groups the backend deliberately did
    // not merge. Bucketing on a location alone collapsed them into one row
    // and hid two CVEs behind a toggle -- a grouping the PR comment for the
    // same scan never rendered. group_size is what makes that impossible.
    const cves = [1, 2, 3].map((n) =>
      finding({
        id: n,
        tool: "trivy",
        rule_id: `CVE-2026-${n}`,
        title: `CVE-2026-${n}`,
        file_path: "requirements.txt",
        line_start: null,
        // A backend that keyed on the location alone would send these three
        // the same key; group_size still says each stands alone.
        group_key: "requirements.txt",
        group_size: 1,
      }),
    );

    const groups = groupFindings(cves);

    expect(groups).toHaveLength(3);
    expect(groups.map((g) => g.findings.length)).toEqual([1, 1, 1]);
    // React keys stay distinct even though the rows share a key.
    expect(new Set(groups.map((g) => g.key)).size).toBe(3);
  });

  it("never takes more members into a bucket than group_size allows", () => {
    // Two real groups of two that happen to share a key: the second pair
    // starts a new bucket rather than overflowing the first.
    const rows = [1, 2, 3, 4].map((n) =>
      finding({ id: n, tool: n % 2 ? "semgrep" : "gitleaks", group_key: "shared", group_size: 2 }),
    );

    const groups = groupFindings(rows);

    expect(groups.map((g) => g.findings.map((f) => f.id))).toEqual([
      [1, 2],
      [3, 4],
    ]);
  });

  it("derives severity and the headline finding from the members", () => {
    // Tools disagree about the same line all the time; the collapsed row has
    // to read at the highest severity present, whichever row arrived first.
    // Derived from the members rather than carried on a row, so a row can
    // never be badged at a severity none of its members has.
    const groups = groupFindings([
      finding({ severity: "Medium" }),
      finding({ id: 2, tool: "gitleaks", title: "AWS access token", severity: "Critical" }),
    ]);

    expect(groups[0].severity).toBe("Critical");
    expect(groups[0].primary.id).toBe(2);
    expect(groups[0].tools).toEqual(["semgrep", "gitleaks"]);
  });

  it("degrades to one group per finding when the response carries no grouping", () => {
    const flat = [
      { ...finding(), group_key: undefined, group_size: undefined },
      { ...GITLEAKS, group_key: undefined, group_size: undefined },
    ];

    expect(groupFindings(flat)).toHaveLength(2);
  });

  it("does not merge on an empty group_key", () => {
    // parse_sarif reports file_path "" for a result with no locations, and
    // "" is not nullish -- it would slip past a `??` guard and bucket every
    // location-less finding in the scan into one row.
    const rows = [
      { ...finding(), file_path: "", group_key: "", group_size: 1 },
      { ...GITLEAKS, file_path: "", group_key: "", group_size: 1 },
    ];

    expect(groupFindings(rows)).toHaveLength(2);
  });

  it("keeps the rows in the order the API sent them", () => {
    const groups = groupFindings([
      finding({ id: 5, group_key: "5@auth.py:12", group_size: 1, file_path: "auth.py", line_start: 12 }),
      finding(),
      GITLEAKS,
    ]);

    expect(groups.map((g) => g.findings.map((f) => f.id))).toEqual([[5], [1, 2]]);
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

  it("renders findings the backend kept apart as separate rows, with nothing hidden", async () => {
    // The page must render the same grouping the PR comment does for the
    // same scan. Three trivy CVEs on one manifest are three findings there,
    // so three rows here -- not one collapsed row labelled "found by: trivy"
    // with two CVEs behind a toggle.
    const cves = [1, 2, 3].map((n) =>
      finding({
        id: n,
        tool: "trivy",
        rule_id: `CVE-2026-${n}`,
        title: `CVE-2026-${n}`,
        file_path: "requirements.txt",
        line_start: null,
        group_key: `${n}@requirements.txt`,
        group_size: 1,
      }),
    );

    await renderFindings(cves, null, /CVE-2026-1/);

    for (const n of [1, 2, 3]) {
      // Title and location line both name it, hence getAll.
      expect(screen.getAllByText(new RegExp(`CVE-2026-${n}`)).length).toBeGreaterThan(0);
    }
    expect(screen.queryByText(/found by:/)).toBeNull();
    expect(screen.queryByText(/Show \d+ findings/)).toBeNull();
    expect(screen.queryByText(/grouped into/)).toBeNull();
  });

  it("badges a group at its most severe member", async () => {
    await renderFindings([
      finding({ severity: "Low" }),
      { ...GITLEAKS, severity: "Critical" },
    ]);

    const header = screen.getByText(/found by: semgrep, gitleaks/).closest("button");
    expect(header?.textContent).toContain("Critical");
  });

  it("leaves an ungrouped finding as a plain row", async () => {
    await renderFindings([
      finding({ group_key: "1@README.md:7", group_size: 1 }),
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

// PRGuardrailFinding cannot carry a FindingRow/FindingDetailDrawer -- it has
// no priority_score/sla_days/kev_listed/state (see the boundary-adaptation
// comment on PrGuardrailFindingRow in pr-guardrail-log.tsx) -- but severity
// itself is real data both objects share, and SEVERITY_BORDER_COLOR is the
// one token finding-row.tsx/finding-group-row.tsx use to accent it. These
// pin that this file reads the same token rather than a color of its own,
// which is exactly the kind of drift the KEV/EPSS badges once had between
// the grouped and flat finding rows, one rendering down.
describe("severity-first visual hierarchy", () => {
  it("gives a standalone finding row the shared left-border severity accent", async () => {
    await renderFindings(
      [finding({ severity: "Critical", group_key: "1@README.md:7", group_size: 1 })],
      null,
      /Detected AWS access key ID/,
    );

    const row = screen.getByText("Detected AWS access key ID").closest('[id^="finding-"]');
    expect(row).not.toBeNull();
    // SEVERITY_BORDER_COLOR.Critical, not a hand-rolled destructive class --
    // a change to the shared token has to reach this row automatically.
    expect(row?.className).toContain("border-l-destructive");
  });

  it("gives a grouped row's header the accent for the group's own (highest-member) severity", async () => {
    await renderFindings([
      finding({ severity: "Low" }),
      { ...GITLEAKS, severity: "Critical" },
    ]);

    const header = screen.getByText(/found by: semgrep, gitleaks/).closest("div.rounded-md");
    expect(header).not.toBeNull();
    // The group is badged Critical (the more severe member), so the accent
    // has to follow that, not either member's row individually.
    expect(header?.className).toContain("border-l-destructive");
  });
});
