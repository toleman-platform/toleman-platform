import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { FindingGroupRow, daysSince, formatAge, groupSubject } from "./finding-group-row";
import type { Finding, FindingGroup } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

const findings = vi.fn();
const bulkTriage = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      findings: (...args: unknown[]) => findings(...args),
      bulkTriage: (...args: unknown[]) => bulkTriage(...args),
    },
  };
});

function makeGroup(overrides: Partial<FindingGroup> = {}): FindingGroup {
  return {
    tool: "trivy-license",
    rule_id: "license:LGPL-3.0-or-later",
    category: "License",
    title: "LGPL-3.0-or-later license detected in @img/sharp-libvips-linux-arm",
    severity: "High",
    grouped: true,
    finding_count: 11,
    target_count: 1,
    file_count: 1,
    max_priority_score: 320,
    oldest_first_seen: new Date(Date.now() - 64 * 24 * 60 * 60 * 1000).toISOString(),
    newest_last_seen: new Date().toISOString(),
    max_epss: null,
    kev_count: 0,
    representative_id: 38,
    representative_file_path: "frontend/package-lock.json",
    representative_target_id: 1,
    sla_days: null,
    sla_violated: false,
    fixability: "unknown",
    ...overrides,
  };
}

function makeMember(id: number): Finding {
  return {
    id,
    target_id: 1,
    tool: "trivy-license",
    rule_id: "license:LGPL-3.0-or-later",
    title: `LGPL-3.0-or-later license detected in package-${id}`,
    description: "",
    file_path: "frontend/package-lock.json",
    line_start: null,
    line_end: null,
    severity: "High",
    priority_score: 320,
    branch: "main",
    state: "Open",
    cve_id: null,
    epss_score: null,
    kev_listed: false,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    sla_days: null,
    sla_violated: false,
    category: "License",
  } as Finding;
}

// Reset between tests, not just between files: several tests here assert on
// *whether* the members endpoint was called at all, and a spy carrying calls
// from a previous test turns "never fetched" into a false failure.
beforeEach(() => {
  findings.mockReset();
  bulkTriage.mockReset();
});

describe("groupSubject", () => {
  it("leads with the licence, not the identical `license:` prefix", () => {
    // The prefix is the same on every licence row; the licence is the part
    // that differs, so it has to come first or the reader scans to find it.
    expect(groupSubject(makeGroup())).toBe("LGPL-3.0-or-later");
  });

  it("leaves a rule id that is already distinctive alone", () => {
    expect(groupSubject(makeGroup({ rule_id: "CVE-2024-1234" }))).toBe("CVE-2024-1234");
  });
});

describe("daysSince / formatAge", () => {
  it("counts whole days against a fixed clock", () => {
    const now = Date.parse("2026-03-10T00:00:00Z");
    expect(daysSince("2026-03-08T00:00:00Z", now)).toBe(2);
  });

  it("never reports a negative age for a finding stamped in the future", () => {
    const now = Date.parse("2026-03-10T00:00:00Z");
    expect(daysSince("2026-03-20T00:00:00Z", now)).toBe(0);
  });

  it("returns 0 rather than NaN for an unparseable timestamp", () => {
    expect(daysSince("not a date", Date.now())).toBe(0);
  });

  it("switches to years once a day count stops being readable", () => {
    expect(formatAge(64)).toBe("64d");
    expect(formatAge(400)).toBe("1y 35d");
  });
});

describe("FindingGroupRow", () => {
  it("shows how many findings one decision covers", () => {
    render(<FindingGroupRow group={makeGroup()} />);
    expect(screen.getByText("11")).not.toBeNull();
    expect(screen.getByText("LGPL-3.0-or-later")).not.toBeNull();
  });

  it("fetches members only when expanded, and only once", async () => {
    findings.mockResolvedValue({ items: [makeMember(38), makeMember(37)], total: 2 });
    render(<FindingGroupRow group={makeGroup()} />);

    expect(findings).not.toHaveBeenCalled();

    const row = screen.getByRole("button", { expanded: false });
    fireEvent.click(row);
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());
    expect(findings).toHaveBeenCalledTimes(1);

    // Collapse and re-expand: navigation, not a reason to re-hit the API.
    fireEvent.click(screen.getByRole("button", { expanded: true }));
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());
    expect(findings).toHaveBeenCalledTimes(1);
  });

  it("asks the API for exactly this group's members", async () => {
    findings.mockResolvedValue({ items: [], total: 0 });
    render(<FindingGroupRow group={makeGroup()} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));

    await waitFor(() =>
      expect(findings).toHaveBeenCalledWith(
        expect.objectContaining({ tool: "trivy-license", rule_id: "license:LGPL-3.0-or-later" }),
      ),
    );
  });

  it("never fetches for an ungrouped row, which would reveal only itself", async () => {
    render(<FindingGroupRow group={makeGroup({ grouped: false, category: "Secrets", finding_count: 1 })} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));

    await waitFor(() => expect(screen.getByText(/is one incident with its own clock/)).not.toBeNull());
    expect(findings).not.toHaveBeenCalled();
  });

  it("applies one rationale to every member of the group", async () => {
    findings.mockResolvedValue({ items: [makeMember(38), makeMember(37)], total: 2 });
    bulkTriage.mockResolvedValue({ updated: 2, items: [] });
    const onTriaged = vi.fn();
    render(<FindingGroupRow group={makeGroup()} onTriaged={onTriaged} />);

    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());

    fireEvent.change(screen.getByLabelText(/Rationale, applied to all 2 findings/), {
      target: { value: "Build-time binary, not distributed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    await waitFor(() =>
      expect(bulkTriage).toHaveBeenCalledWith([38, 37], "Accepted Risk", "Build-time binary, not distributed"),
    );
    await waitFor(() => expect(onTriaged).toHaveBeenCalled());
  });

  it("surfaces a KEV count rather than a bare flag", () => {
    render(<FindingGroupRow group={makeGroup({ kev_count: 3 })} />);
    expect(screen.getByText(/KEV/).textContent).toContain("×3");
  });

  it("says nothing about EPSS below the notable threshold", () => {
    render(<FindingGroupRow group={makeGroup({ max_epss: 0.02 })} />);
    expect(screen.queryByText(/EPSS/)).toBeNull();
  });
});
