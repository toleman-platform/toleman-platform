import { api, type Target } from "@/lib/api";
import { GithubOrgLogsFilterBar, GithubOrgLogsList } from "@/components/features/logs";
import { PageHeader } from "@/components/ui/page-header";
import { PartialFailureBanner } from "@/components/ui/partial-failure-banner";
import { settleOrNull, settledOr } from "@/std-lib";
// Plain module, not the "use client" component; a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";

// Page size is now a user preference read off the URL (25/50/100),
// defaulting to 25. See components/ui/activity-pagination.tsx.

function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

export default async function GithubOrgLogsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const targetIdRaw = firstValue(sp.target_id);
  const target_id = targetIdRaw ? Number(targetIdRaw) : undefined;
  const date_from = firstValue(sp.date_from);
  const date_to = firstValue(sp.date_to);
  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSize = pageSizeFromParams(sp.page_size);

  const [activityResult, [targetsList, targetsFailed]] = await Promise.all([
    settleOrNull(api.orgActivity({ target_id, date_from, date_to, page, page_size: pageSize })),
    // settledOr, not `.catch(() => [])`: the repository <select> below cannot
    // tell an org with no connected repos from an org whose repo list did not
    // load, and the second one reads as the first -- "All repositories" over
    // an empty list, on the page whose whole claim is that it shows activity
    // from every repository you've connected. Secondary to the activity feed,
    // so it degrades the page rather than failing it, but the boolean has to
    // survive to the screen (std-lib/async.ts).
    settledOr(api.targets(), [] as Target[]),
  ]);
  const result = activityResult ?? { items: [], total: 0 };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="GitHub Org Logs"
        description="A true organization-level audit trail is a GitHub Enterprise feature not available on personal accounts. In its place, this page shows real commit activity pulled live from every repository you've connected; nothing here is simulated or backfilled."
      />

      <PartialFailureBanner
        sources={[
          {
            label: "Repository list",
            failed: targetsFailed,
            consequence: "the repository filter is empty, so filtering by repository is unavailable",
          },
        ]}
      />

      <GithubOrgLogsFilterBar targets={targetsList} />
      {/* `failed` (not a page-level ternary around ErrorState/GithubOrgLogsList)
          is what makes "no activity" and "we couldn't load activity" structurally
          unable to converge -- same as the audit-log page beside this one. */}
      <GithubOrgLogsList
        events={result.items}
        total={result.total}
        page={page}
        pageSize={pageSize}
        failed={activityResult === null}
      />
    </div>
  );
}
