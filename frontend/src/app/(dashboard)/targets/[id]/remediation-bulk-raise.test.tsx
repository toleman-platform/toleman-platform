import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { RemediationBulkRaise } from "./remediation-bulk-raise";
import type { RemediationPrBatch } from "@/types";

// (#247 follow-up) Two properties CodeRabbit's review caught that are easy
// to get wrong with this shape of async-batch-plus-polling component:
//   1. A transient poll failure must not strand the panel forever --
//      lib/poll.ts's pollUntilSettled gives up after ONE fetch error, so
//      the component has to offer its own way back in.
//   2. "Hide" while the batch is still running must not destroy the only
//      thing (batch_id) that lets progress be restored, or silently cancel
//      the still-running poll and re-enable "Raise all" mid-flight.
const { raiseAllFixPrs, getRaiseAllFixPrsBatch } = vi.hoisted(() => ({
  raiseAllFixPrs: vi.fn(),
  getRaiseAllFixPrsBatch: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ api: { raiseAllFixPrs, getRaiseAllFixPrsBatch } }));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
}));

function batch(overrides: Partial<RemediationPrBatch> = {}): RemediationPrBatch {
  return {
    batch_id: 1,
    target_id: 7,
    status: "running",
    total: 2,
    succeeded: 0,
    failed: 0,
    started_at: "2026-01-01T00:00:00Z",
    completed_at: null,
    items: [],
    ...overrides,
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  raiseAllFixPrs.mockReset();
  getRaiseAllFixPrsBatch.mockReset();
});
afterEach(() => vi.useRealTimers());

/** pollUntilSettled waits one interval before its first request. */
async function advanceOnePoll() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2000);
  });
}

describe("RemediationBulkRaise", () => {
  it("starts a batch and shows live progress as polling reports it", async () => {
    raiseAllFixPrs.mockResolvedValue({ batch_id: 1, total: 2, status: "running" });
    getRaiseAllFixPrsBatch.mockResolvedValue(
      batch({
        items: [
          { package: "starlette", status: "succeeded", error: "", pr_url: "https://github.com/a/b/pull/1", pr_number: 1, completed_at: "2026-01-01T00:01:00Z" },
          { package: "axios", status: "running", error: "", pr_url: null, pr_number: null, completed_at: null },
        ],
      }),
    );

    render(<RemediationBulkRaise targetId={7} totalPackages={2} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Raise all (2)" }));
    });
    await advanceOnePoll();

    expect(screen.getByText("starlette")).not.toBeNull();
    expect(screen.getByText("axios")).not.toBeNull();
    expect(screen.getByRole("link", { name: "PR" })).not.toBeNull();
  });

  it("disables Raise all while a batch is running, so a second click can't double-dispatch", async () => {
    raiseAllFixPrs.mockResolvedValue({ batch_id: 1, total: 2, status: "running" });
    getRaiseAllFixPrsBatch.mockResolvedValue(batch());

    render(<RemediationBulkRaise targetId={7} totalPackages={2} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Raise all (2)" }));
    });

    expect(screen.getByRole("button", { name: "Raise all (2)" })).toHaveProperty("disabled", true);
  });

  it("keeps polling a running batch after hide, and can be shown again", async () => {
    raiseAllFixPrs.mockResolvedValue({ batch_id: 1, total: 2, status: "running" });
    getRaiseAllFixPrsBatch.mockResolvedValue(batch());

    render(<RemediationBulkRaise targetId={7} totalPackages={2} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Raise all (2)" }));
    });
    await advanceOnePoll();

    fireEvent.click(screen.getByRole("button", { name: "hide" }));
    expect(screen.queryByRole("button", { name: "hide" })).toBeNull();
    expect(screen.getByText(/Raising PRs for 2 packages… \(show\)/)).not.toBeNull();

    // Batch finishes while hidden -- the poll effect never unmounted, so
    // the next tick still reaches the (still-mounted, just visually
    // collapsed) component.
    getRaiseAllFixPrsBatch.mockResolvedValue(batch({ status: "completed", succeeded: 2 }));
    await advanceOnePoll();

    fireEvent.click(screen.getByText("Show results"));
    expect(screen.getByText("Done: 2 succeeded, 0 failed")).not.toBeNull();
  });

  it("offers a retry after a poll failure, and resumes progress on retry", async () => {
    raiseAllFixPrs.mockResolvedValue({ batch_id: 1, total: 1, status: "running" });
    getRaiseAllFixPrsBatch.mockRejectedValueOnce(new Error("network blip"));

    render(<RemediationBulkRaise targetId={7} totalPackages={1} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Raise all (1)" }));
    });
    await advanceOnePoll();

    expect(screen.getByText(/network blip/)).not.toBeNull();

    getRaiseAllFixPrsBatch.mockResolvedValue(batch({ total: 1, status: "completed", succeeded: 1 }));
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await advanceOnePoll();

    expect(screen.getByText("Done: 1 succeeded, 0 failed")).not.toBeNull();
    expect(screen.queryByText(/network blip/)).toBeNull();
  });

  it("closes and discards state only once the batch has actually completed", async () => {
    raiseAllFixPrs.mockResolvedValue({ batch_id: 1, total: 1, status: "running" });
    getRaiseAllFixPrsBatch.mockResolvedValue(batch({ total: 1, status: "completed", succeeded: 1 }));

    render(<RemediationBulkRaise targetId={7} totalPackages={1} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Raise all (1)" }));
    });
    await advanceOnePoll();

    fireEvent.click(screen.getByRole("button", { name: "close" }));
    // Raise all is available again -- the batch is genuinely finished, not
    // just hidden -- and the panel itself is gone.
    expect(screen.queryByText("Done: 1 succeeded, 0 failed")).toBeNull();
    expect(screen.getByRole("button", { name: "Raise all (1)" })).toHaveProperty("disabled", false);
  });
});
