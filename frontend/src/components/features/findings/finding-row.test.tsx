import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingRow } from "./finding-row";
import type { Finding } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    target_id: 1,
    tool: "trivy",
    rule_id: "CVE-2024-0001",
    title: "Vulnerable dependency",
    description: "",
    file_path: "package.json",
    line_start: null,
    line_end: null,
    severity: "High",
    priority_score: 320,
    branch: "main",
    state: "Open",
    cve_id: "CVE-2024-0001",
    epss_score: null,
    kev_listed: false,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    sla_days: null,
    sla_violated: false,
    category: "Vulnerability",
    ...overrides,
  } as Finding;
}

describe("FirstSeenAge (via FindingRow, showScore=false)", () => {
  it("renders a real day count for a well-formed first_seen", () => {
    const now = Date.parse("2026-03-10T00:00:00Z");
    vi.spyOn(Date, "now").mockReturnValue(now);
    render(<FindingRow finding={makeFinding({ first_seen: "2026-03-08T00:00:00Z" })} showScore={false} />);
    expect(screen.getByText("2d")).not.toBeNull();
    vi.restoreAllMocks();
  });

  // The defect: Math.max(0, Math.floor((now - NaN) / DAY)) is NaN, which
  // React renders as the literal string "NaNd" -- a nonsense age presented
  // with the same font-bold confidence as a real one. daysSince
  // (finding-group-row.tsx) already guards this identical computation with
  // `if (Number.isNaN(then)) return 0`; this is that same guard applied to
  // FirstSeenAge, so an unparseable timestamp reads as 0d instead of NaNd.
  it("falls back to 0d rather than NaNd for an unparseable first_seen", () => {
    render(<FindingRow finding={makeFinding({ first_seen: "not a date" })} showScore={false} />);
    expect(screen.getByText("0d")).not.toBeNull();
    expect(screen.queryByText(/NaN/)).toBeNull();
  });
});
