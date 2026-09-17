import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { PackageRemediation, RemediationCoverage } from "@/types";
import { RemediationPlanView } from "./remediation-plan";

// ActivityPagination and RemediationBulkRaise (#247 follow-up) read/write
// the URL and router; only navigation is mocked so the rest of each still
// renders for real, same as audit-log-list.test.tsx's identical mock.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/targets/7",
  useSearchParams: () => new URLSearchParams(),
}));

// (#247) These assert the two honesty properties backend/app/core/
// remediation.py's docstring calls out, plus the failed/empty distinction
// AGENTS.md requires everywhere on this surface. All three are the kind of
// defect that is invisible in a screenshot of the happy path -- an
// `unresolved` array silently dropped, or an empty plan rendered as an
// all-clear -- so they are asserted on directly rather than left to a visual
// check.
//
// The empty plan is four states, not one (see `emptyPlanCopy`), and the
// difference between them is the difference between "we checked and there is
// no fix" and "nobody has checked". Each gets its own test below, including
// the negative assertion that the unmeasured cases never state the measured
// sentence -- which is the exact defect this tab shipped with.

function makeFix(overrides: Partial<PackageRemediation["fixes"][number]> = {}): PackageRemediation["fixes"][number] {
  return {
    cve_id: "CVE-2023-0001",
    finding_id: 1,
    severity: "High",
    title: "Improper input validation",
    ...overrides,
  };
}

function makePlan(overrides: Partial<PackageRemediation> = {}): PackageRemediation {
  return {
    package: "starlette",
    ecosystem: "PyPI",
    upgrade_to: "0.40.0",
    fixes: [makeFix()],
    fixes_count: 1,
    unresolved: [],
    highest_severity: "High",
    ...overrides,
  };
}

/** Fully-enriched coverage for one fixable finding: the populated default. */
function makeCoverage(overrides: Partial<RemediationCoverage> = {}): RemediationCoverage {
  return {
    cve_findings: 1,
    distinct_cves: 1,
    enriched_findings: 1,
    findings_with_advisory: 1,
    findings_with_fix_data: 1,
    ...overrides,
  };
}

describe("RemediationPlanView", () => {
  it("renders an ErrorState, not an empty plan, when the fetch failed", () => {
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={null} failed={true} />,
    );

    // A failed fetch must not read as "zero upgrades exist" -- that would be
    // the exact false-all-clear AGENTS.md §5 forbids.
    expect(screen.getByRole("alert")).not.toBeNull();
    expect(container.textContent).toContain("couldn't be loaded");
    expect(container.textContent).not.toContain("No fixed versions published");
    expect(container.textContent).not.toContain("No CVE findings on this target");
  });

  it("says there is nothing to plan against when no open finding carries a CVE", () => {
    const coverage = makeCoverage({
      cve_findings: 0,
      distinct_cves: 0,
      enriched_findings: 0,
      findings_with_advisory: 0,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    expect(screen.getByText("No CVE findings on this target")).not.toBeNull();
    // Nothing CVE-shaped to group is not the same statement as "no upgrade
    // resolves these", and must not borrow its wording.
    expect(container.textContent).not.toContain("names a fixed version");
    expect(container.textContent).toContain("can still be open");
    const link = screen.getByRole("link", { name: /Go to Vulnerabilities/i }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/targets/7?tab=vulnerabilities");
  });

  it("says enrichment has not run, and claims nothing about fixes, when no CVE is enriched", () => {
    // The shipped defect: 40 open CVE findings, zero enrichment rows, and an
    // empty state asserting that no upgrade resolves any of them.
    const coverage = makeCoverage({
      cve_findings: 40,
      distinct_cves: 31,
      enriched_findings: 0,
      findings_with_advisory: 0,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    expect(screen.getByText("No advisory data fetched yet")).not.toBeNull();
    expect(container.textContent).toContain("None of this target's 40 open CVE findings has advisory data yet");
    expect(container.textContent).toContain("no fix has been ruled out");
    // Not one word asserting anything about the fixes themselves.
    expect(container.textContent).not.toContain("names a fixed version");
    expect(container.textContent).not.toContain("No fixed versions published");
  });

  it("does not call a cached failed lookup a measured absence of fixes", () => {
    // Rows exist (something was attempted) but no advisory record came back,
    // so "no fixed version is published" is still not established.
    const coverage = makeCoverage({
      cve_findings: 10,
      distinct_cves: 10,
      enriched_findings: 6,
      findings_with_advisory: 0,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    expect(screen.getByText("No advisory records found")).not.toBeNull();
    expect(container.textContent).toContain("Lookups ran for 6 of 10 open CVE findings");
    expect(container.textContent).toContain("not the same as none existing");
    // The four CVEs nobody has looked up are reported, not absorbed.
    expect(container.textContent).toContain("The other 4 have not been looked up yet");
  });

  it("states a genuine no-fix only when advisories were actually read", () => {
    const coverage = makeCoverage({
      cve_findings: 5,
      distinct_cves: 5,
      enriched_findings: 5,
      findings_with_advisory: 5,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    expect(screen.getByText("No fixed versions published")).not.toBeNull();
    expect(container.textContent).toContain("Advisories cover 5 of 5 open CVE findings");
    expect(container.textContent).toContain("none of them names a fixed version");
    // Full coverage: there is no unchecked remainder to report, and none is
    // invented.
    expect(container.textContent).not.toContain("not been looked up yet");
    // Still not an all-clear.
    expect(container.textContent).toContain("Those findings are still open");
  });

  it("reports partial coverage inside the measured no-fix sentence", () => {
    const coverage = makeCoverage({
      cve_findings: 9,
      distinct_cves: 9,
      enriched_findings: 4,
      findings_with_advisory: 4,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    expect(container.textContent).toContain("Advisories cover 4 of 9 open CVE findings");
    // 4 covered + 0 with no record + 5 never looked up = 9. Every finding is
    // accounted for; the earlier wording reported one remainder computed
    // against a different denominator than the fraction it followed, so a
    // reader subtracting the two got a number no sentence explained.
    expect(container.textContent).toContain("5 have not been looked up yet");
    expect(container.textContent).not.toContain("returned no advisory record");
  });

  it("accounts for every finding when some were looked up and found nothing", () => {
    // The case the old wording lost entirely: 4 covered, 3 looked up with no
    // record, 3 never looked up. Reporting only "the other 3 have not been
    // looked up" left three findings unexplained.
    const coverage = makeCoverage({
      cve_findings: 10,
      distinct_cves: 10,
      enriched_findings: 7,
      findings_with_advisory: 4,
      findings_with_fix_data: 0,
    });
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={coverage} failed={false} />,
    );

    const text = container.textContent ?? "";
    expect(text).toContain("Advisories cover 4 of 10 open CVE findings");
    expect(text).toContain("3 returned no advisory record");
    expect(text).toContain("3 have not been looked up yet");
  });

  it("falls back to an unknown-coverage empty state rather than a negative one", () => {
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={null} failed={false} />,
    );

    expect(screen.getByText("Fix coverage unknown")).not.toBeNull();
    expect(container.textContent).toContain("Advisory coverage for this target is unknown");
    expect(container.textContent).not.toContain("names a fixed version");
  });

  it("treats an out-of-range page as distinct from a genuinely empty plan", () => {
    // resolvedTotal (5) > 0, but this specific page has nothing on it --
    // must not borrow emptyPlanCopy's wording, which is about the whole
    // target having no fixes, not about which page was requested.
    const { container } = render(
      <RemediationPlanView targetId={7} plans={[]} coverage={makeCoverage()} failed={false} total={5} page={3} pageSize={25} />,
    );

    expect(screen.getByText("No upgrades on this page")).not.toBeNull();
    expect(container.textContent).toContain("Page 3 is past the end of this target's 5 upgrades");
    expect(container.textContent).not.toContain("No fixed versions published");
    expect(container.textContent).not.toContain("Fix coverage unknown");
    const link = screen.getByRole("link", { name: /Go to page 1/i }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/targets/7?tab=fix-plan");
    // No pager: ActivityPagination's "Showing X-Y of Z" range math assumes
    // `page` is in range, which this state is defined by NOT being.
    expect(screen.queryByText(/Showing/)).toBeNull();
  });

  it("states what an upgrade leaves behind, not just what it fixes", () => {
    const plan = makePlan({
      package: "axios",
      upgrade_to: "1.7.4",
      fixes: [
        makeFix({ cve_id: "CVE-2024-1111", finding_id: 11, severity: "High", title: "SSRF via redirect" }),
        makeFix({ cve_id: "CVE-2024-2222", finding_id: 12, severity: "Medium", title: "Prototype pollution" }),
      ],
      fixes_count: 2,
      unresolved: [{ cve_id: "CVE-2024-9999", finding_id: 13, severity: "Critical" }],
      highest_severity: "Critical",
    });
    const coverage = makeCoverage({
      cve_findings: 3,
      distinct_cves: 3,
      enriched_findings: 3,
      findings_with_advisory: 3,
      findings_with_fix_data: 2,
    });
    const { container } = render(
      <RemediationPlanView targetId={3} plans={[plan]} coverage={coverage} failed={false} />,
    );

    // What it closes.
    expect(container.textContent).toContain("axios");
    expect(container.textContent).toContain("upgrade to");
    expect(container.textContent).toContain("1.7.4");
    expect(container.textContent).toContain("Fixes 2 of 3 findings on this package");
    expect(container.textContent).toContain("1 left unresolved");
    expect(screen.getByText("CVE-2024-1111")).not.toBeNull();
    expect(screen.getByText("CVE-2024-2222")).not.toBeNull();

    // What it leaves behind -- never hidden, never rounded away.
    expect(container.textContent).toContain("Not fixed by this upgrade");
    expect(screen.getByText("CVE-2024-9999")).not.toBeNull();

    // Never overstated as a bare upgrade recommendation.
    expect(container.textContent).not.toContain("latest");
    expect(container.textContent).not.toContain("recommended");
  });

  it("never fabricates a finding title for an unresolved CVE the backend didn't send one for", () => {
    // RemediationUnresolved carries no `title` (see backend/app/core/
    // remediation.py's second pass) -- this pins the row down to exactly
    // severity + CVE id, so a future edit cannot quietly invent a label.
    const plan = makePlan({
      fixes: [],
      fixes_count: 0,
      unresolved: [{ cve_id: "CVE-2024-8888", finding_id: 21, severity: "Low" }],
    });
    render(
      <RemediationPlanView targetId={3} plans={[plan]} coverage={makeCoverage()} failed={false} />,
    );

    const cve = screen.getByText("CVE-2024-8888");
    const row = cve.closest("a");
    expect(row).not.toBeNull();
    expect(row!.textContent).toBe("LowCVE-2024-8888");
  });

  it("says an upgrade fixes everything only when nothing is left unresolved", () => {
    const plan = makePlan({ fixes_count: 3, unresolved: [] });
    const { container } = render(
      <RemediationPlanView
        targetId={3}
        plans={[plan]}
        coverage={makeCoverage({ cve_findings: 3, distinct_cves: 3, enriched_findings: 3, findings_with_advisory: 3, findings_with_fix_data: 3 })}
        failed={false}
      />,
    );

    expect(container.textContent).toContain("Fixes all 3 findings on this package");
    expect(screen.queryByText("Not fixed by this upgrade")).toBeNull();
  });

  it("preserves the backend's most-findings-closed-first order rather than re-sorting", () => {
    const first = makePlan({ package: "zzz-package", fixes_count: 5 });
    const second = makePlan({ package: "aaa-package", fixes_count: 1 });
    const { container } = render(
      <RemediationPlanView targetId={3} plans={[first, second]} coverage={makeCoverage()} failed={false} />,
    );

    const zIndex = container.textContent!.indexOf("zzz-package");
    const aIndex = container.textContent!.indexOf("aaa-package");
    expect(zIndex).toBeGreaterThanOrEqual(0);
    expect(zIndex).toBeLessThan(aIndex);
  });

  it("does not let a populated plan read as complete when coverage is partial", () => {
    // The upgrades shown are real; the 12 CVEs nobody has looked up are
    // neither fixed nor fix-less. A list that says nothing about them reads
    // as the full answer.
    const coverage = makeCoverage({
      cve_findings: 20,
      distinct_cves: 18,
      enriched_findings: 8,
      findings_with_advisory: 8,
      findings_with_fix_data: 3,
    });
    const { container } = render(
      <RemediationPlanView targetId={3} plans={[makePlan()]} coverage={coverage} failed={false} />,
    );

    expect(container.textContent).toContain("1 upgrade would close open findings on this target.");
    expect(container.textContent).toContain("built on the 8 of 20 open CVE findings with an advisory");
    expect(container.textContent).toContain("12 have not been looked up yet");
  });

  it("keeps the caveat when every CVE was looked up and almost nothing came back", () => {
    // An upstream outage looks like full coverage if the caveat keys on
    // lookups attempted: enriched_findings reaches cve_findings while only
    // two advisories actually exist, so the plan rests on almost no data and
    // the old condition suppressed the warning entirely.
    const coverage = makeCoverage({
      cve_findings: 20,
      distinct_cves: 20,
      enriched_findings: 20,
      findings_with_advisory: 2,
      findings_with_fix_data: 1,
    });
    const { container } = render(
      <RemediationPlanView targetId={3} plans={[makePlan()]} coverage={coverage} failed={false} />,
    );

    const text = container.textContent ?? "";
    expect(text).toContain("built on the 2 of 20 open CVE findings with an advisory");
    expect(text).toContain("18 returned no advisory record");
  });

  it("adds no coverage caveat when every CVE finding has been looked up", () => {
    const { container } = render(
      <RemediationPlanView
        targetId={3}
        plans={[makePlan()]}
        coverage={makeCoverage({ cve_findings: 4, distinct_cves: 4, enriched_findings: 4, findings_with_advisory: 4, findings_with_fix_data: 4 })}
        failed={false}
      />,
    );

    expect(container.textContent).toContain("1 upgrade would close open findings on this target.");
    expect(container.textContent).not.toContain("Advisory data covers");
    expect(container.textContent).not.toContain("not been looked up yet");
  });
});
