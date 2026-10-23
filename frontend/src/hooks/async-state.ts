/**
 * Pure async-request reducer, separate from the React hook for transition testing.
 * Retain prior data during refresh and rejection. idle permits deferred requests
 * without a false loading state.
 */
export type AsyncStatus = "idle" | "loading" | "success" | "error";

export type AsyncState<T> = {
  status: AsyncStatus;
  data: T | null;
  error: Error | null;
  /** True while a request is in flight *and* previous data is still shown. */
  isRefreshing: boolean;
  /** Monotonic id of the most recently *started* request. Used to discard
   * out-of-order responses, the classic bug where a slow first request
   * lands after a fast second and overwrites it. */
  requestId: number;
};

export type AsyncAction<T> =
  | { type: "reset" }
  | { type: "start"; requestId: number }
  | { type: "resolve"; requestId: number; data: T }
  | { type: "reject"; requestId: number; error: Error };

export function initialAsyncState<T>(initialData: T | null = null): AsyncState<T> {
  return {
    status: initialData === null ? "idle" : "success",
    data: initialData,
    error: null,
    isRefreshing: false,
    requestId: 0,
  };
}

export function asyncReducer<T>(state: AsyncState<T>, action: AsyncAction<T>): AsyncState<T> {
  switch (action.type) {
    case "reset":
      return initialAsyncState<T>();

    case "start":
      return {
        ...state,
        status: "loading",
        // Keep whatever we already had: a refetch should not blank the view.
        error: null,
        isRefreshing: state.data !== null,
        requestId: action.requestId,
      };

    case "resolve":
      // Ignore anything that is not the newest request. Without this, a slow
      // response can clobber a newer one and the UI shows data the user has
      // already navigated away from.
      if (action.requestId !== state.requestId) return state;
      return {
        status: "success",
        data: action.data,
        error: null,
        isRefreshing: false,
        requestId: state.requestId,
      };

    case "reject":
      if (action.requestId !== state.requestId) return state;
      return {
        status: "error",
        // Previous data survives an error on purpose, stale rows beside an
        // error banner beat an empty screen, and the caller can tell which
        // is which.
        data: state.data,
        error: action.error,
        isRefreshing: false,
        requestId: state.requestId,
      };

    default:
      return state;
  }
}

export { toError } from "@/std-lib";

