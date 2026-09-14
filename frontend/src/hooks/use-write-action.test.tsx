import { describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { useWriteAction } from "./use-write-action";

/** A promise this test resolves by hand, so "in flight" is an assertable
 * state rather than a timing guess. */
function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useWriteAction", () => {
  it("starts idle with nothing to report", () => {
    const { result } = renderHook(() => useWriteAction("Triage failed"));
    expect(result.current.submitting).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("flags submitting while the work is in flight and clears it after", async () => {
    const d = deferred<void>();
    const { result } = renderHook(() => useWriteAction("Triage failed"));

    let done: Promise<boolean>;
    act(() => {
      done = result.current.run(() => d.promise);
    });
    await waitFor(() => expect(result.current.submitting).toBe(true));

    await act(async () => {
      d.resolve();
      await done;
    });
    expect(result.current.submitting).toBe(false);
  });

  it("reports the failure instead of swallowing it", async () => {
    // The whole point. The previous `try { ... } finally { setSubmitting(false) }`
    // shape re-enabled the buttons and said nothing at all, leaving no way to
    // tell a failed write from a succeeded one whose list had not refreshed.
    const { result } = renderHook(() => useWriteAction("Triage failed"));

    let outcome: boolean | undefined;
    await act(async () => {
      outcome = await result.current.run(async () => {
        throw new Error("403 Forbidden");
      });
    });

    expect(outcome).toBe(false);
    expect(result.current.error).toBe("403 Forbidden");
    // Still re-enabled: the user must be able to retry.
    expect(result.current.submitting).toBe(false);
  });

  it("falls back to the action-specific message when the throw carries none", async () => {
    const { result } = renderHook(() => useWriteAction("Triage failed"));
    await act(async () => {
      await result.current.run(async () => {
        throw new Error("");
      });
    });
    // Not "Something went wrong" -- DESIGN_SYSTEM.md §20 asks for contextual
    // errors, which is why the fallback is a constructor argument.
    expect(result.current.error).toBe("Triage failed");
  });

  it("does not run the success path when the write throws", async () => {
    // Callers put their post-write cleanup (clear the selection, collapse the
    // row, refresh the router) after the await inside `work`. That placement
    // is only safe because a throw skips it -- collapsing a group row after a
    // failed triage is the most convincing possible lie about what happened.
    const afterWrite = vi.fn();
    const { result } = renderHook(() => useWriteAction("Group triage failed"));

    await act(async () => {
      await result.current.run(async () => {
        await Promise.reject(new Error("network"));
        afterWrite();
      });
    });

    expect(afterWrite).not.toHaveBeenCalled();
    expect(result.current.error).toBe("network");
  });

  it("clears a stale error when the next attempt starts", async () => {
    const { result } = renderHook(() => useWriteAction("Triage failed"));

    await act(async () => {
      await result.current.run(async () => {
        throw new Error("first failure");
      });
    });
    expect(result.current.error).toBe("first failure");

    let outcome: boolean | undefined;
    await act(async () => {
      outcome = await result.current.run(async () => {});
    });

    expect(outcome).toBe(true);
    // A success must not leave the previous attempt's banner contradicting it.
    expect(result.current.error).toBeNull();
  });

  it("clears the error on demand", async () => {
    const { result } = renderHook(() => useWriteAction("Triage failed"));
    await act(async () => {
      await result.current.run(async () => {
        throw new Error("nope");
      });
    });
    act(() => result.current.clearError());
    expect(result.current.error).toBeNull();
  });
});
