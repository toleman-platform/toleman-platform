import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Unmount between tests. Without this, a live region from a previous test is
// still in the document and `getByRole("status")` matches the wrong one;
// which is exactly the kind of false pass that makes accessibility tests
// worthless.
afterEach(() => cleanup());
