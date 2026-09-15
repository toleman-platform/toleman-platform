import { afterEach } from "vitest";
import { cleanup, configure } from "@testing-library/react";

// Testing Library's 1s default is a wall-clock budget, and under `vitest run`
// these files execute in parallel worker threads that each transform and mount
// a page's worth of components. A page-level test that resolves in ~200ms on
// its own can blow past 1s purely from scheduling, which shows up as a test
// that fails only in the full suite. Raised so a timeout means the code never
// settled, not that the machine was busy.
configure({ asyncUtilTimeout: 5000 });

// Unmount between tests. Without this, a live region from a previous test is
// still in the document and `getByRole("status")` matches the wrong one;
// which is exactly the kind of false pass that makes accessibility tests
// worthless.
afterEach(() => cleanup());

// jsdom 30 implements localStorage (verified directly: `new JSDOM("", {url})`
// exposes it), but vitest 2.1.9's jsdom environment does not surface it as a
// global here -- `window.localStorage` is undefined in every test. Without a
// real implementation, code that persists a user preference silently takes
// its storage-unavailable branch, so a test for the persisted path cannot
// tell "saved and read back" apart from "storage was never there" -- and a
// test for the UNavailable path passes for the wrong reason.
//
// The methods go on `Storage.prototype` rather than onto a plain object so
// that `vi.spyOn(Storage.prototype, "getItem")` still intercepts them. A
// test simulating a browser that refuses storage does it that way, and a
// polyfill holding its own methods would make those spies silently inert.
if (typeof window !== "undefined" && !window.localStorage) {
  const store = new Map<string, string>();
  Storage.prototype.getItem = (k: string) => (store.has(k) ? store.get(k)! : null);
  Storage.prototype.setItem = (k: string, v: string) => void store.set(k, String(v));
  Storage.prototype.removeItem = (k: string) => void store.delete(k);
  Storage.prototype.clear = () => store.clear();
  Storage.prototype.key = (i: number) => [...store.keys()][i] ?? null;
  const storage = Object.create(Storage.prototype) as Storage;
  Object.defineProperty(storage, "length", { get: () => store.size });
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true, writable: true });
}
