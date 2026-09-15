import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { PackageRemediation } from "@/types";
import { RemediationPlanView } from "./remediation-plan";

// (#247) These assert the two honesty properties backend/app/core/
// remediation.py's docstring calls out, plus the failed/empty distinction
// AGENTS.md requires everywhere on this surface. All three are the kind of
// defect that is invisible in a screenshot of the happy path -- an
// `unresolved` array silently dropped, or an empty plan rendered as an
// all-clear -- so they are asserted on directly rather than left to a visual
// check.

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

describe("RemediationPlanView", () => {
  it("renders an ErrorState, not an empty plan, when the fetch failed", () => {
    const { container } = render(<RemediationPlanView targetId={7} plans={[]} failed={true} />);

    // A failed fetch must not read as "zero upgrades exist" -- that would be
    // the exact false-all-clear AGENTS.md §5 forbids.
    expect(screen.getByRole("alert")).not.toBeNull();
    expect(container.textContent).toContain("couldn't be loaded");
    expect(screen.queryByText(/No known fixes/i)).toBeNull();
  });

  it("distinguishes a genuinely empty plan from 'nothing to do' and points at Vulnerabilities", () => {
    render(<RemediationPlanView targetId={7} plans={[]} failed={false} />);

    expect(screen.getByText(/No known fixes yet/i)).not.toBeNull();
    // The whole point of this empty state: it must not read as an all-clear.
    expect(screen.getByText(/isn't the same as nothing to do/i)).not.toBeNull();
    const link = screen.getByRole("link", { name: /Go to Vulnerabilities/i }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/targets/7?tab=vulnerabilities");
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
    const { container } = render(<RemediationPlanView targetId={3} plans={[plan]} failed={false} />);

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
    render(<RemediationPlanView targetId={3} plans={[plan]} failed={false} />);

    const cve = screen.getByText("CVE-2024-8888");
    const row = cve.closest("a");
    expect(row).not.toBeNull();
    expect(row!.textContent).toBe("LowCVE-2024-8888");
  });

  it("says an upgrade fixes everything only when nothing is left unresolved", () => {
    const plan = makePlan({ fixes_count: 3, unresolved: [] });
    const { container } = render(<RemediationPlanView targetId={3} plans={[plan]} failed={false} />);

    expect(container.textContent).toContain("Fixes all 3 findings on this package");
    expect(screen.queryByText("Not fixed by this upgrade")).toBeNull();
  });

  it("preserves the backend's most-findings-closed-first order rather than re-sorting", () => {
    const first = makePlan({ package: "zzz-package", fixes_count: 5 });
    const second = makePlan({ package: "aaa-package", fixes_count: 1 });
    const { container } = render(<RemediationPlanView targetId={3} plans={[first, second]} failed={false} />);

    const zIndex = container.textContent!.indexOf("zzz-package");
    const aIndex = container.textContent!.indexOf("aaa-package");
    expect(zIndex).toBeGreaterThanOrEqual(0);
    expect(zIndex).toBeLessThan(aIndex);
  });
});
