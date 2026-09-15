import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { TargetTabs, VULNERABILITY_TAB_QUEUE, vulnerabilityTabCount } from "./target-tabs";
import { QUEUES, queueFilters, POLICY_CATEGORIES } from "@/lib/findings-view";

// The badge beside the Vulnerabilities tab used to read the "All findings"
// count, so a repository with 40 open vulnerabilities and 148 licence rows
// announced "Vulnerabilities (188)" and then opened on a 40-row list. A
// licence obligation on a transitive dependency is a policy question, not a
// vulnerability.

/** Per-queue counts in QUEUES order, which is how page.tsx assembles them. */
function counts(byQueue: Partial<Record<(typeof QUEUES)[number]["id"], number | null>>): (number | null)[] {
  return QUEUES.map((q) => byQueue[q.id] ?? null);
}

describe("vulnerabilityTabCount", () => {
  it("counts the queue that excludes licence findings, not every open finding", () => {
    const value = vulnerabilityTabCount(counts({ action: 40, license: 148, resolved: 9, all: 188 }));

    expect(value).toBe(40);
  });

  it("uses a queue whose filters really do exclude the licence category", () => {
    // Guards the line above from agreeing with itself: if the badge's queue
    // were switched to one that includes licence rows, this fails.
    const filters = queueFilters(VULNERABILITY_TAB_QUEUE);

    expect(filters.exclude_category).toEqual(POLICY_CATEGORIES);
    expect(filters.category).toBe(undefined);
    expect(filters.resolved).toBe(false);
  });

  it("is undefined, not zero, when the count could not be fetched", () => {
    const value = vulnerabilityTabCount(counts({ action: null, license: 148, all: 188 }));

    expect(value).toBe(undefined);
  });

  it("keeps a real zero", () => {
    const value = vulnerabilityTabCount(counts({ action: 0, license: 148, all: 148 }));

    expect(value).toBe(0);
  });
});

describe("TargetTabs badge", () => {
  it("renders the vulnerability count beside the label", () => {
    render(<TargetTabs targetId={7} active="overview" vulnerabilityCount={40} />);

    const tab = screen.getByRole("link", { name: /Vulnerabilities/ });
    expect(tab.textContent).toBe("Vulnerabilities (40)");
  });

  it("omits the badge entirely rather than claiming zero when the count is unknown", () => {
    render(<TargetTabs targetId={7} active="overview" />);

    const tab = screen.getByRole("link", { name: /Vulnerabilities/ });
    expect(tab.textContent).toBe("Vulnerabilities");
  });

  it("shows a measured zero", () => {
    render(<TargetTabs targetId={7} active="overview" vulnerabilityCount={0} />);

    const tab = screen.getByRole("link", { name: /Vulnerabilities/ });
    expect(tab.textContent).toBe("Vulnerabilities (0)");
  });
});
