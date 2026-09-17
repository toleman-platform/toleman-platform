import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { PackageRemediation, RemediationCoverage } from "@/types";
import { WorkspaceRemediationPlanView } from "./workspace-remediation-plan";

// ActivityPagination (rendered by the populated view below) reads/writes
// the URL; only its navigation is mocked so the pagination row itself
// still renders for real, same as remediation-plan.test.tsx's identical
// mock and audit-log-list.test.tsx's original.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

// (#247 follow-up) The workspace-wide Fix Plan reuses the same honesty
// properties and empty-state discipline the per-target tab's own tests pin
// down (backend/app/core/remediation.py's docstring), reworded for "across
// your targets" rather than "on this target" -- these focus on what's
// actually different here: rows from different targets are never merged,
// and each one says which target it's for.

function makeFix(overrides: Partial<PackageRemediation["fixes"][number]> = {}): PackageRemediation["fixes"][number] {
  return { cve_id: "CVE-2023-0001", finding_id: 1, severity: "High", title: "Improper input validation", ...overrides };
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
    target_id: 7,
    target_name: "acme-api",
    ...overrides,
  };
}

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

describe("WorkspaceRemediationPlanView", () => {
  it("renders an ErrorState, not an empty plan, when the fetch failed", () => {
    render(<WorkspaceRemediationPlanView plans={[]} coverage={null} failed={true} />);
    expect(screen.getByRole("alert")).not.toBeNull();
    expect(screen.getByText(/couldn't be loaded/)).not.toBeNull();
  });

  it("says there is nothing to plan against, phrased across targets, when nothing has a CVE", () => {
    const coverage = makeCoverage({ cve_findings: 0, distinct_cves: 0, enriched_findings: 0, findings_with_advisory: 0, findings_with_fix_data: 0 });
    const { container } = render(<WorkspaceRemediationPlanView plans={[]} coverage={coverage} failed={false} />);
    expect(screen.getByText("No CVE findings across your targets")).not.toBeNull();
    const link = screen.getByRole("link", { name: /Browse targets/i }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/targets");
    expect(container.textContent).not.toContain("names a fixed version");
  });

  it("treats an out-of-range page as distinct from a genuinely empty plan", () => {
    const { container } = render(
      <WorkspaceRemediationPlanView plans={[]} coverage={makeCoverage()} failed={false} total={5} page={3} pageSize={25} />,
    );
    expect(screen.getByText("No upgrades on this page")).not.toBeNull();
    expect(container.textContent).toContain("Page 3 is past the end of these 5 upgrades");
    const link = screen.getByRole("link", { name: /Go to page 1/i }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/findings?tab=fix-plan");
    expect(screen.queryByText(/Showing/)).toBeNull();
  });

  it("renders the same package on two different targets as two independent rows", () => {
    const rowA = makePlan({ target_id: 1, target_name: "repo-a", upgrade_to: "0.40.0" });
    const rowB = makePlan({ target_id: 2, target_name: "repo-b", upgrade_to: "0.41.0" });
    render(<WorkspaceRemediationPlanView plans={[rowA, rowB]} coverage={makeCoverage()} failed={false} total={2} />);

    expect(screen.getByText("repo-a")).not.toBeNull();
    expect(screen.getByText("repo-b")).not.toBeNull();
    // Two separate upgrade targets shown, never collapsed into one.
    expect(screen.getByText("0.40.0")).not.toBeNull();
    expect(screen.getByText("0.41.0")).not.toBeNull();
  });

  it("links each row's target name back to that target's own Fix plan tab", () => {
    const plan = makePlan({ target_id: 42, target_name: "acme-api" });
    render(<WorkspaceRemediationPlanView plans={[plan]} coverage={makeCoverage()} failed={false} />);
    const link = screen.getByRole("link", { name: "acme-api" }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/targets/42?tab=fix-plan");
  });

  it("states the whole-set total, not just this page's length, in the summary sentence", () => {
    const plan = makePlan();
    const { container } = render(
      <WorkspaceRemediationPlanView plans={[plan]} coverage={makeCoverage({ cve_findings: 20 })} failed={false} total={20} />,
    );
    expect(container.textContent).toContain("20 upgrades would close open findings across your targets.");
  });

  it("preserves backend order across targets rather than re-sorting", () => {
    const first = makePlan({ target_id: 1, target_name: "zzz-repo", package: "zzz-package", fixes_count: 5 });
    const second = makePlan({ target_id: 2, target_name: "aaa-repo", package: "aaa-package", fixes_count: 1 });
    const { container } = render(
      <WorkspaceRemediationPlanView plans={[first, second]} coverage={makeCoverage()} failed={false} total={2} />,
    );
    const firstIndex = container.textContent!.indexOf("zzz-package");
    const secondIndex = container.textContent!.indexOf("aaa-package");
    expect(firstIndex).toBeGreaterThanOrEqual(0);
    expect(firstIndex).toBeLessThan(secondIndex);
  });
});
