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
