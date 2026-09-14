import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { GithubOrgLogsList } from "./github-org-logs-list";
import type { OrgActivityEvent } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => "/github-org-logs",
  useSearchParams: () => new URLSearchParams(),
}));

function commit(overrides: Partial<OrgActivityEvent> = {}): OrgActivityEvent {
  return {
    sha: "abc1234",
    message: "fix: handle empty response",
    author: "dev@example.com",
    date: "2026-09-01T00:00:00Z",
    url: "https://github.com/acme/repo/commit/abc1234",
    target: "acme/repo",
    target_id: 1,
    ...overrides,
  };
}

// Same class of bug as AuditLogList (#465): this is the "other log surface"
// admin M25 names, so it gets the identical failed-vs-empty guarantee.
describe("GithubOrgLogsList empty vs failed", () => {
  it("renders the failed state, not the empty state, when the fetch behind it failed", () => {
    render(<GithubOrgLogsList events={[]} total={0} page={1} pageSize={25} failed />);

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("couldn't be loaded");
    expect(screen.queryByText("No activity found")).toBeNull();
  });

  it("renders the genuine empty state when the fetch succeeded with zero rows", () => {
    render(<GithubOrgLogsList events={[]} total={0} page={1} pageSize={25} />);

    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("No activity found")).not.toBeNull();
  });

  it("defaults to the non-failed rendering when the prop is omitted, so the existing page.tsx caller is unaffected", () => {
    render(<GithubOrgLogsList events={[commit()]} total={1} page={1} pageSize={25} />);

    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("fix: handle empty response")).not.toBeNull();
  });

  it("keys rows by target+sha rather than position, so same-message commits on different repos both render", () => {
    // Regression guard for `key={i}`: two commits that would render
    // identical link text if either target_id or sha were dropped from the
    // key.
    render(
      <GithubOrgLogsList
        events={[
          commit({ target: "acme/repo-a", target_id: 1, sha: "aaa1111" }),
          commit({ target: "acme/repo-b", target_id: 2, sha: "bbb2222" }),
        ]}
        total={2}
        page={1}
        pageSize={25}
      />,
    );

    expect(screen.getByText("acme/repo-a")).not.toBeNull();
    expect(screen.getByText("acme/repo-b")).not.toBeNull();
  });
});
