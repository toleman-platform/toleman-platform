"use client";

import { useCallback, useEffect, useMemo, useReducer, useRef } from "react";
import { AsyncState, asyncReducer, initialAsyncState, toError } from "./async-state";

/**
 * One fetch, one state machine (issue #210).
 *
 * Sixteen files hand-rolled this: a `useEffect`, a `loading` boolean, an
 * `error` string, and -- inconsistently -- a `cancelled` guard in the
 * cleanup. The ones missing that guard set state after unmount and could
 * apply a stale response over a newer one.
 *
 * The state transitions live in async-state.ts as a pure reducer so they can
 * be tested exhaustively without a DOM; this hook is only the React wiring
 * around it.
 */
export type UseAsyncDataOptions = {
  /**
   * Skip the request entirely. For a fetch that depends on a selection the
   * user has not made yet -- the state stays `idle` rather than pretending
   * to load something nobody asked for.
   */
  enabled?: boolean;
  /**
   * Values that should trigger a refetch when they change, same contract as
   * a dependency array. Kept explicit rather than inferred from the fetcher
   * identity, because an inline arrow is a new function every render and
   * would refetch forever.
   */
  deps?: readonly unknown[];
};

export type UseAsyncDataResult<T> = AsyncState<T> & {
  /** Re-run the request, keeping current data visible while it is in flight. */
  refetch: () => void;
  /** True only for the very first load, when there is nothing to show yet.
   * This is what should drive a skeleton; `isRefreshing` should not. */
  isInitialLoading: boolean;
};

export function useAsyncData<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  { enabled = true, deps = [] }: UseAsyncDataOptions = {},
): UseAsyncDataResult<T> {
  const [state, dispatch] = useReducer(asyncReducer<T>, undefined, () => initialAsyncState<T>());

  // The fetcher is nearly always an inline arrow, so it changes identity on
  // every render. Holding it in a ref keeps `run` stable, which is what stops
  // the effect below from looping.
  //
  // Synced in an effect rather than assigned during render: writing a ref
  // mid-render is unsafe under concurrent rendering, where a render can be
  // discarded and replayed, and react-hooks/refs rejects it. This effect is
  // declared before the fetching effect below, so on any given commit the ref
  // is current before a request is started.
  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  const requestIdRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  const run = useCallback(() => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    const requestId = ++requestIdRef.current;
    dispatch({ type: "start", requestId });

    fetcherRef.current(controller.signal).then(
      (data) => {
        // An aborted request is not a failure -- the caller moved on, and
        // surfacing "AbortError" as an error banner would be a lie.
        if (controller.signal.aborted) return;
        dispatch({ type: "resolve", requestId, data });
      },
      (thrown) => {
        if (controller.signal.aborted) return;
        dispatch({ type: "reject", requestId, error: toError(thrown) });
      },
    );
  }, []);

  useEffect(() => {
    if (!enabled) return;
    run();
    return () => abortRef.current?.abort();
    // `deps` is the caller's declared dependency list; `run` is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, run, ...deps]);

  return useMemo(
    () => ({
      ...state,
      refetch: run,
      isInitialLoading: state.status === "loading" && state.data === null,
    }),
    [state, run],
  );
}
