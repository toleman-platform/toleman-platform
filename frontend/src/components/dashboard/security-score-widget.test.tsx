import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { WidgetBody } from "./widgets";
import type { SecurityScore } from "@/lib/api";

// The Security Score widget's honesty rules (frontend/AGENTS.md 1.4).
//
// Two things were being rendered as confident numbers that no measurement
// supported: a trend component scored 0/100 on an instance with no seven-day
// history, and an "open findings" count that added licence-compliance rows to
// the vulnerability count the score was actually computed from.
//
// The scope picker fetches targets and groups on mount; neither is under test
// here, so both resolve empty.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      targets: () => Promise.resolve([]),
      groups: () => Promise.resolve([]),
    },
  };
});

const TREND_NOTE = "no data from 7 days ago to compare against";

/**
 * A two-repo workspace with 188 open findings, of which 40 are vulnerabilities
 * and 148 are licence rows, and no history from a week ago. Deliberately the
 * shape reported from the live instance.
 */
function scoreWith(over: Partial<SecurityScore> = {}): SecurityScore {
  return {
    score: 68.6,
    grade: "D",
    target_count: 2,
    weakest_component: "coverage",
    components: {
      findings: {
        score: 13,
        weight: 35,
        measurable: true,
        open_findings: 188,
        open_vulnerabilities: 40,
        license_findings_excluded: 148,
        weighted_severity_sum: 134,
        avg_weighted_severity_per_target: 67,
      },
      sla: { score: 100, weight: 25, measurable: true, with_sla: 0, in_violation: 0, compliant: 0, note: null },
      coverage: {
        score: 0,
        weight: 15,
        measurable: true,
        scanned_targets: 0,
        total_targets: 2,
        deactivated_targets: 0,
        window_days: 30,
        note: null,
      },
      fp_rate: { score: 100, weight: 10, measurable: true, false_positives: 0, total_findings: 188, fp_rate: 0 },
      trend: {
        score: null,
        weight: 15,
        measurable: false,
        direction: "unknown",
        current_weighted_sum: 134,
        prior_weighted_sum: null,
        window_days: 7,
        note: TREND_NOTE,
      },
    },
    ...over,
  };
}

function renderScore(data: SecurityScore) {
  render(<WidgetBody entry={{ widget_id: "security_score", data }} />);
}

describe("SecurityScoreWidget - a component that could not be measured", () => {
  it("reads as no reading, not as 0/100", async () => {
    renderScore(scoreWith());

    const row = (await screen.findByText("Trend (7d) score")).closest("div");
    expect(row).not.toBeNull();
    const rowText = row?.textContent ?? "";

    expect(rowText.includes("—")).toBe(true);
    // The whole defect in one assertion: this row used to read "0/100".
    expect(rowText.includes("/100")).toBe(false);
  });

  it("says why it could not be measured, in the words the server used", async () => {
    renderScore(scoreWith());

    const row = (await screen.findByText("Trend (7d) score")).closest("div");
    expect((row?.textContent ?? "").includes(TREND_NOTE)).toBe(true);
  });

  it("draws no meter and no direction arrow for it, while measured components keep both", async () => {
    renderScore(scoreWith());

    const trendRow = (await screen.findByText("Trend (7d) score")).closest("div");
    // A meter reports a value; there is no value to report. An arrow would
    // claim posture held steady, improved or worsened over a week nothing is
    // known about.
    expect(trendRow?.querySelector('[role="progressbar"]')).toBeNull();
    expect(trendRow?.querySelector("svg")).toBeNull();

    // Not the coverage row: it is this scope's weakest component, so its
    // label also appears inside the penalty callout.
    const measuredRow = screen.getByText("Open findings score").closest("div");
    expect(measuredRow?.querySelector('[role="progressbar"]')).not.toBeNull();
  });

  it("is never named as the score penalty", async () => {
    // Every measured component is perfect and the trend is unknown, so there
    // is nothing costing score and nothing to blame.
    renderScore(scoreWith({ weakest_component: null, score: 100, grade: "A" }));

    await screen.findByText("Trend (7d) score");
    expect(screen.queryByText(/Score penalty/)).toBeNull();
  });

  it("still lets a genuinely weak measured component be named", async () => {
    renderScore(scoreWith());

    const penaltyBox = (await screen.findByText(/Score penalty/)).closest("div");
    const penaltyText = penaltyBox?.textContent ?? "";
    expect(penaltyText.includes("Scan coverage score")).toBe(true);
    expect(penaltyText.includes("Trend")).toBe(false);
  });

  it("shows no gauge at all when nothing could be measured", async () => {
    renderScore(scoreWith({ score: null, grade: null, weakest_component: null }));

    expect(await screen.findByText(/Not enough data to score this scope yet/)).toBeTruthy();
    expect(screen.queryByText("Open findings score")).toBeNull();
  });
});

describe("SecurityScoreWidget - licence findings are not vulnerabilities", () => {
  it("prints the vulnerability count the score was computed from, not the total", async () => {
    renderScore(scoreWith());

    const row = (await screen.findByText("Open findings score")).closest("div");
    const rowText = row?.textContent ?? "";

    expect(rowText.includes("40 open on default branch")).toBe(true);
    expect(rowText.includes("148 licence excluded")).toBe(true);
    // 148 of the 188 contribute nothing to the 13/100 beside them, so 188 is
    // the one number that must not appear here.
    expect(rowText.includes("188")).toBe(false);
  });

  it("omits the licence aside when there are no licence findings to exclude", async () => {
    const clean = scoreWith();
    clean.components.findings = {
      ...clean.components.findings,
      open_findings: 40,
      open_vulnerabilities: 40,
      license_findings_excluded: 0,
    };
    renderScore(clean);

    const row = (await screen.findByText("Open findings score")).closest("div");
    const rowText = row?.textContent ?? "";

    expect(rowText.includes("40 open on default branch")).toBe(true);
    expect(rowText.includes("licence excluded")).toBe(false);
  });
});
