import { api } from "@/lib/api";
import { GithubOrgLogsFilterBar } from "@/components/github-org-logs-filter-bar";
import { GithubOrgLogsList } from "@/components/github-org-logs-list";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";
// Plain module, not the "use client" component -- a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";

// Page size is now a user preference read off the URL (25/50/100),
// defaulting to 25. See components/activity-pagination.tsx.

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

  const [activityResult, targets] = await Promise.all([
    settleOrNull(api.orgActivity({ target_id, date_from, date_to, page, page_size: pageSize })),
    api.targets().catch(() => []),
  ]);
  const result = activityResult ?? { items: [], total: 0 };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">GitHub Org Logs</h1>
        <p className="text-sm text-muted-foreground">
          A true organization-level audit trail is a GitHub Enterprise feature not available on personal accounts. In
          its place, this page shows real commit activity pulled live from every repository you&apos;ve connected —
          nothing here is simulated or backfilled.
        </p>
      </div>
      <GithubOrgLogsFilterBar targets={targets} />
      {activityResult === null ? (
        <ErrorState description="GitHub org activity couldn't be loaded from the API." action={<ReloadButton />} />
      ) : (
        <GithubOrgLogsList events={result.items} total={result.total} page={page} pageSize={pageSize} />
      )}
    </div>
  );
}
