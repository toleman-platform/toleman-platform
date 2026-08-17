import { describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { useAsyncData } from "./use-async-data";

/** A promise whose resolution this test controls, so races are deterministic
 * rather than timing-dependent. */
function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useAsyncData", () => {
  it("fetches on mount and exposes the data", async () => {
    const { result } = renderHook(() => useAsyncData(async () => ["a", "b"]));
    await waitFor(() => expect(result.current.status).toBe("success"));
    expect(result.current.data).toEqual(["a", "b"]);
    expect(result.current.isInitialLoading).toBe(false);
  });

  it("flags the first load so a skeleton shows only then", async () => {
    const d = deferred<string[]>();
    const { result } = renderHook(() => useAsyncData(() => d.promise));
    expect(result.current.isInitialLoading).toBe(true);
    await act(async () => d.resolve(["x"]));
    expect(result.current.isInitialLoading).toBe(false);
  });

  it("does not show a skeleton on refetch, only a refreshing flag", async () => {
    // A list that blanks every time it revalidates reads as broken.
    let calls = 0;
    const { result } = renderHook(() =>
      useAsyncData(async () => {
        calls += 1;
        return [`run-${calls}`];
      }),
    );
    await waitFor(() => expect(result.current.status).toBe("success"));

    act(() => result.current.refetch());
    expect(result.current.isInitialLoading).toBe(false);
    expect(result.current.data).toEqual(["run-1"]); // previous data still shown

    await waitFor(() => expect(result.current.data).toEqual(["run-2"]));
  });

  it("surfaces a rejection as an Error", async () => {
    const { result } = renderHook(() =>
      useAsyncData(async () => {
        throw new Error("boom");
      }),
    );
    await waitFor(() => expect(result.current.status).toBe("error"));
    expect(result.current.error?.message).toBe("boom");
  });

  it("normalises a thrown string", async () => {
    const { result } = renderHook(() =>
      useAsyncData(async () => {
        throw "plain string";
      }),
    );
    await waitFor(() => expect(result.current.error?.message).toBe("plain string"));
  });

  it("does not fetch when disabled, and stays idle", async () => {
    const fetcher = vi.fn(async () => ["x"]);
    const { result } = renderHook(() => useAsyncData(fetcher, { enabled: false }));
    expect(fetcher).not.toHaveBeenCalled();
    // Idle, not loading: nothing was requested, so a spinner would be a lie.
    expect(result.current.status).toBe("idle");
    expect(result.current.isInitialLoading).toBe(false);
  });

  it("fetches once the gate opens", async () => {
    const fetcher = vi.fn(async () => ["x"]);
    const { rerender, result } = renderHook(({ on }) => useAsyncData(fetcher, { enabled: on }), {
      initialProps: { on: false },
    });
    expect(fetcher).not.toHaveBeenCalled();

    rerender({ on: true });
    await waitFor(() => expect(result.current.status).toBe("success"));
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("refetches when a declared dependency changes", async () => {
    const fetcher = vi.fn(async () => ["x"]);
    const { rerender } = renderHook(({ id }) => useAsyncData(fetcher, { deps: [id] }), {
      initialProps: { id: 1 },
    });
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());

    rerender({ id: 2 });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  });

  it("does not loop when the fetcher is an inline arrow", async () => {
    // The classic infinite-refetch bug: an inline function is a new identity
    // every render, so keying the effect on it never settles.
    let calls = 0;
    const { rerender } = renderHook(() =>
      useAsyncData(async () => {
        calls += 1;
        return calls;
      }),
    );
    await waitFor(() => expect(calls).toBe(1));
    rerender();
    rerender();
    await new Promise((r) => setTimeout(r, 20));
    expect(calls).toBe(1);
  });

  it("aborts the in-flight request on unmount", async () => {
    let seenSignal: AbortSignal | null = null;
    const { unmount } = renderHook(() =>
      useAsyncData((signal) => {
        seenSignal = signal;
        return new Promise<string[]>(() => {});
      }),
    );
    expect(seenSignal!.aborted).toBe(false);
    unmount();
    expect(seenSignal!.aborted).toBe(true);
  });

  it("ignores a response that arrives after the request was aborted", async () => {
    // Setting state after unmount is the warning everyone has seen; the
    // subtler harm is applying data the user has already navigated away from.
    const d = deferred<string[]>();
    const { result, unmount } = renderHook(() => useAsyncData(() => d.promise));
    unmount();
    await act(async () => d.resolve(["late"]));
    expect(result.current.data).toBeNull();
  });

  it("keeps the newest result when a slow request resolves last", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    let call = 0;

    const { result } = renderHook(() =>
      useAsyncData(() => {
        call += 1;
        return call === 1 ? first.promise : second.promise;
      }),
    );

    act(() => result.current.refetch());
    await act(async () => second.resolve("newer"));
    await act(async () => first.resolve("older"));

    await waitFor(() => expect(result.current.data).toBe("newer"));
  });
});
