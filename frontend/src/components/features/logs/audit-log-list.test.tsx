import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditLogList } from "./audit-log-list";
import type { AuditEvent } from "@/lib/api";

// ActivityPagination reads/writes the URL; only its navigation is mocked so
// the pagination row itself still renders for real.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => "/audit-log",
  useSearchParams: () => new URLSearchParams(),
}));

function event(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    type: "triage",
    timestamp: "2026-09-01T00:00:00Z",
    actor: "dev@example.com",
    summary: "moved 1 finding to Resolved",
    reason: "",
    grouped_count: 1,
    expand: null,
    ...overrides,
  };
}

// Item #465-class bug: a compliance surface must never let "nothing
// happened" and "we don't know what happened" render as the same screen.
describe("AuditLogList empty vs failed", () => {
  it("renders the failed state, not the empty state, when the fetch behind it failed", () => {
    render(<AuditLogList events={[]} total={0} page={1} pageSize={25} failed />);

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("couldn't be loaded");
    expect(screen.queryByText("No audit events found")).toBeNull();
  });

  it("renders the genuine empty state when the fetch succeeded with zero rows", () => {
    render(<AuditLogList events={[]} total={0} page={1} pageSize={25} />);

    expect(screen.queryByRole("alert")).toBeNull();
    const empty = screen.getByText("No audit events found");
    expect(empty).not.toBeNull();
  });

  it("defaults to the non-failed rendering when the prop is omitted", () => {
    // Existing/hypothetical callers that don't pass `failed` must keep
    // today's behavior -- this prop is additive, not a breaking change.
    render(<AuditLogList events={[event()]} total={1} page={1} pageSize={25} />);

    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("moved 1 finding to Resolved")).not.toBeNull();
  });

  it("renders one card per event without collapsing distinct rows onto the same key", () => {
    // Regression guard for `key={i}`: two events with everything but their
    // summary identical must still both render. An index key wouldn't have
    // caught this (index keys "work" until the list reorders), but a
    // duplicate-content case is exactly what a natural key must not conflate.
    render(
      <AuditLogList
        events={[
          event({ summary: "moved 1 finding to Resolved" }),
          event({ summary: "moved 1 finding to Suppressed" }),
        ]}
        total={2}
        page={1}
        pageSize={25}
      />,
    );

    expect(screen.getByText("moved 1 finding to Resolved")).not.toBeNull();
    expect(screen.getByText("moved 1 finding to Suppressed")).not.toBeNull();
  });
});
