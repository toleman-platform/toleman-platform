import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { SecurityLog } from "./security-log";

const { securityAuditLog } = vi.hoisted(() => ({
  securityAuditLog: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { securityAuditLog },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/admin",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

describe("Security Log - Audit Log cross-link (the other direction of the fix)", () => {
  it("links back to the Audit Log for scan and triage history", async () => {
    securityAuditLog.mockResolvedValue({ items: [], total: 0 });

    render(<SecurityLog />);

    const link = (await screen.findByRole("link", {
      name: /View scan and triage history in the Audit Log/i,
    })) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/audit-log");
  });
});
