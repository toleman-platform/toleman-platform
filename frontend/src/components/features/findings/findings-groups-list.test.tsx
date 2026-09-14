import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingsGroupsList } from "./findings-groups-list";
import type { FindingGroup } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  // ActivityPagination (rendered whenever total > 0) also calls usePathname.
  usePathname: () => "/findings",
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      findings: vi.fn().mockResolvedValue({ items: [], total: 0 }),
    },
  };
});

function makeGroup(overrides: Partial<FindingGroup> = {}): FindingGroup {
  return {
    tool: "trivy-license",
    rule_id: "license:LGPL-3.0-or-later",
    category: "License",
    title: "LGPL-3.0-or-later license detected",
    severity: "High",
    grouped: true,
    finding_count: 11,
    target_count: 1,
    file_count: 1,
    max_priority_score: 320,
    oldest_first_seen: new Date().toISOString(),
    newest_first_seen: new Date().toISOString(),
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

// core M11: the header/body split has to carry real table semantics --
// `table` > `rowgroup` > `row` > `columnheader`/`cell` -- so a screen reader
// can announce each row's cells against these headers, matching
// FindingGroupRow's own `role="row"`/`role="cell"` half of the fix.
describe("FindingsGroupsList", () => {
  it("structures the grouped list as a labelled table with column headers", () => {
    const { container } = render(
      <FindingsGroupsList groups={[makeGroup()]} total={1} totalFindings={11} page={1} pageSize={25} />,
    );

    const table = container.querySelector('[role="table"]');
    expect(table).not.toBeNull();
    expect(table?.getAttribute("aria-label")).toBeTruthy();

    const headers = Array.from(container.querySelectorAll('[role="columnheader"]')).map((el) => el.textContent);
    expect(headers).toEqual(["", "Severity", "Subject", "Findings", "Signals", "Oldest"]);
  });

  it("still renders the empty state instead of an empty table when nothing matches", () => {
    render(<FindingsGroupsList groups={[]} total={0} totalFindings={0} page={1} pageSize={25} />);
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getByText(/No findings/)).not.toBeNull();
  });
});
