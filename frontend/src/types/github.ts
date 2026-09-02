/**
 * GitHub repository integration, commit events, pull requests, and org activity.
 */

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
 * Pull request record with associated scan status.
 */
export type PullRequest = {
  number: number;
  title: string;
  author: string;
  state: string;
  created_at: string;
  merged_at: string | null;
  url: string;
  scan_status: string;
};
