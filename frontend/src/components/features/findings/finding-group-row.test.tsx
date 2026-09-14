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
    newest_first_seen: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
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

  it("asks the API for exactly this group's members, under the list's own filters", async () => {
    // Not objectContaining: the whole defect was filters being *absent*, and a
    // containment assertion cannot see a missing key. The member list is what
    // group triage writes to, so it has to be drawn from the same filters the
    // row's count came from.
    findings.mockResolvedValue({ items: [], total: 0 });
    const memberQuery = { resolved: false, exclude_category: ["License"], severity: ["High"] };
    render(<FindingGroupRow group={makeGroup()} memberQuery={memberQuery} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));

    await waitFor(() =>
      expect(findings).toHaveBeenCalledWith({
        resolved: false,
        exclude_category: ["License"],
        severity: ["High"],
        tool: "trivy-license",
        rule_id: "license:LGPL-3.0-or-later",
        page: 1,
        page_size: 200,
      }),
    );
  });

  it("pages until it has every member, so triage reaches all of them", async () => {
    const firstPage = Array.from({ length: 200 }, (_, i) => makeMember(i + 1));
    const secondPage = Array.from({ length: 40 }, (_, i) => makeMember(i + 201));
    findings
      .mockResolvedValueOnce({ items: firstPage, total: 240 })
      .mockResolvedValueOnce({ items: secondPage, total: 240 });
    bulkTriage.mockResolvedValue({ updated: 240, items: [] });

    render(<FindingGroupRow group={makeGroup({ finding_count: 240 })} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));

    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    await waitFor(() => expect(bulkTriage).toHaveBeenCalled());
    expect(bulkTriage.mock.calls[0][0]).toHaveLength(240);
  });

  it("refuses to triage a group it could not fully load, and says so", async () => {
    // 1,400 members, a 1,000 fetch cap: closing 1,000 of them would leave 400
    // behind a decision the reader believes is finished.
    // Distinct ids per page, as a real API returns: repeating one page's ids
    // would produce duplicate React keys and drown any genuine warning.
    findings.mockImplementation(({ page }: { page: number }) => ({
      items: Array.from({ length: 200 }, (_, i) => makeMember((page - 1) * 200 + i + 1)),
      total: 1400,
    }));

    render(<FindingGroupRow group={makeGroup({ finding_count: 1400 })} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));

    await waitFor(() => expect(screen.getByText(/Showing 1000 of 1400/)).not.toBeNull());
    expect(screen.getByRole("button", { name: "Accepted Risk" }).hasAttribute("disabled")).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));
    expect(bulkTriage).not.toHaveBeenCalled();
  });

  it("drops the cached members after a triage so a second click cannot re-triage", async () => {
    findings.mockResolvedValue({ items: [makeMember(38), makeMember(37)], total: 2 });
    bulkTriage.mockResolvedValue({ updated: 2, items: [] });

    render(<FindingGroupRow group={makeGroup()} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());

    fireEvent.click(screen.getByRole("button", { name: "False Positive" }));
    await waitFor(() => expect(bulkTriage).toHaveBeenCalledTimes(1));

    // Collapsed, cache cleared: re-expanding re-reads rather than replaying
    // stale ids whose state has already changed.
    await waitFor(() => expect(screen.queryByText(/package-38/)).toBeNull());
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2));
  });

  it("says so when a group triage fails, instead of looking like it worked", async () => {
    // The defect: `try { ... } finally { setSubmitting(false) }` with no
    // `catch`. A rejected bulkTriage re-enabled the buttons and changed
    // nothing else, which is indistinguishable from a success whose list has
    // not refreshed -- on a single click that can move 148 findings.
    findings.mockResolvedValue({ items: [makeMember(38), makeMember(37)], total: 2 });
    bulkTriage.mockRejectedValue(new Error("502 Bad Gateway"));

    render(<FindingGroupRow group={makeGroup()} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());

    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    // The API's own message, in an alert so it is announced and not merely
    // drawn.
    const alert = await waitFor(() => screen.getByRole("alert"));
    expect(alert.textContent).toContain("502 Bad Gateway");
    expect(alert.textContent).toContain("Group triage failed");

    // Everything the success path does must NOT have happened: the row stays
    // expanded over its members, so the reader can see what was not triaged.
    expect(screen.getByText(/package-38/)).not.toBeNull();
    expect(screen.getByRole("button", { expanded: true })).not.toBeNull();
    // ...and the buttons are usable again, so a retry is possible.
    expect(screen.getByRole("button", { name: "Accepted Risk" }).hasAttribute("disabled")).toBe(false);
  });

  it("does not claim the findings were left unchanged, which it cannot know", async () => {
    // A rejected request may still have applied some or all of the writes
    // before failing. Replacing one false certainty ("done") with another
    // ("nothing happened") would repeat the bug in the opposite direction.
    findings.mockResolvedValue({ items: [makeMember(38)], total: 1 });
    bulkTriage.mockRejectedValue(new Error("timeout"));

    render(<FindingGroupRow group={makeGroup()} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    await waitFor(() => expect(screen.getByText(/package-38/)).not.toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Accepted Risk" }));

    const alert = await waitFor(() => screen.getByRole("alert"));
    expect(alert.textContent).toMatch(/may not have been updated/i);
    expect(alert.textContent).not.toMatch(/no findings were (changed|updated)/i);
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
