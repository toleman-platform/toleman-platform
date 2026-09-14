/**
 * GitHub repository integration, commit events, pull requests, and org activity.
 */

import type { Nullable } from "@/std-lib";

/**
 * Git commit event details from repository activity feeds.
 */
export type CommitEvent = {
  sha: string;
  message: string;
  author: string;
  date: string;
  url: string;
};

/**
 * Organization-wide commit activity item associated with a target repository.
 */
export type OrgActivityEvent = CommitEvent & {
  target: string;
  target_id: number;
};

/**
 * Filter parameters for querying organization activity.
 */
export type OrgActivityQuery = {
  target_id?: number;
  date_from?: string;
  date_to?: string;
  page?: number;
  page_size?: number;
};

/**
 * Paginated envelope for organization activity events.
 */
export type OrgActivityResult = {
  items: OrgActivityEvent[];
  total: number;
};

/**
 * Lifecycle state of a pull request. GitHub itself only reports open/closed;
 * "merged" is derived server-side (a closed PR with a merged_at) because
 * closed-without-merging and merged are different outcomes to a reviewer.
 */
export type PullRequestState = "open" | "closed" | "merged";

/**
 * Pull request record joined to the target's latest PR Guardrail scan.
 *
 * `scan_status` is that scan's status ("passed"/"blocked"/...), or
 * "not scanned" when this PR has never been through the guardrail.
 * `latest_scan_id` is what lets a PR row expand into the vulnerabilities that
 * scan actually found; it is null exactly when scan_status is "not scanned".
 */
export type PullRequest = {
  number: number;
  title: string;
  author: string;
  state: PullRequestState;
  created_at: string;
  merged_at: Nullable<string>;
  url: string;
  scan_status: string;
  latest_scan_id: Nullable<number>;
  new_findings_count: number;
  highest_new_severity: Nullable<string>;
};
