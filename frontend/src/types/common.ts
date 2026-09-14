/**
 * Common shared domain primitives and lifecycle types.
 */

/**
 * Generic status representation for asynchronous Celery tasks and long-running platform jobs
 * (e.g. Scans, Discovery runs, SBOM generation, Batch Integration).
 */
export type RunStatus = "running" | "completed" | "failed";

/**
 * Metadata about the running backend API instance (GET /health).
 * Used for container health checking and environment verification.
 */
export type BuildInfo = {
  /** Healthcheck status reported by the backend (e.g. "ok") */
  status: string;
  /** Semantic version string of the platform release */
  version: string;
  /** Git commit SHA from which the backend image was built */
  commit: string;
  /** Redacted database host/port/database connection target */
  database: string;
};

/**
 * Result returned by the global search endpoint (GET /api/search?q=...).
 */
export type SearchResults = {
  findings: import("./findings").Finding[];
  targets: import("./targets").Target[];
};
