/**
 * The async-request state machine, as a pure reducer (issue #210).
 *
 * Deliberately separated from the React hook in use-async-data.ts. Sixteen
 * files in this codebase hand-rolled `loading`/`error`/`data` triples, and the
 * bugs were always in the *transitions*, a stale response overwriting a
 * newer one, `loading` left true after an error, a refetch blanking the
 * screen instead of showing the previous data. Those are reducer bugs, and a
 * reducer can be tested exhaustively in Node without a DOM.
 *
 * Two decisions worth stating, because they are what make refetch feel right:
 *
 *   1. `data` is retained across a refetch. A list that blanks to a skeleton
 *      every time it revalidates reads as broken. Callers distinguish the
 *      first load (`status === "loading"`, no data yet) from a background
 *      refresh (`isRefreshing`, data still present).
 *   2. A rejected request never clears previously good data. Showing stale
 *      rows next to an error banner is more useful than showing nothing, and
 *      the caller can still tell the difference.
 */

/** Discrete lifecycle state. `idle` exists so a request can be deferred
 * (e.g. waiting on a workspace selection) without faking a loading spinner
 * for something that was never requested. */
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

/** Normalises whatever a rejected promise carried into a real Error. Callers
 * throw strings, objects and Errors; the UI should not have to care. */
export function toError(thrown: unknown): Error {
  if (thrown instanceof Error) return thrown;
  if (typeof thrown === "string") return new Error(thrown);
  return new Error("Something went wrong");
}
