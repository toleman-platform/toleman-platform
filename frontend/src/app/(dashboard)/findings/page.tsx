import { api } from "@/lib/api";
import { FindingsFilterBar } from "@/components/findings-filter-bar";
import { FindingsList } from "@/components/findings-list";
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

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const severity = firstValue(sp.severity);
  const tool = firstValue(sp.tool);
  const state = firstValue(sp.state);
  const search = firstValue(sp.search);
  const targetIdRaw = firstValue(sp.target_id);
  const target_id = targetIdRaw ? Number(targetIdRaw) : undefined;
  const groupIdRaw = firstValue(sp.group_id);
  const group_id = groupIdRaw ? Number(groupIdRaw) : undefined;
  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSize = pageSizeFromParams(sp.page_size);

  const [findingsResult, targets, tools, groups] = await Promise.all([
    settleOrNull(api.findings({ severity, tool, state, search, target_id, group_id, page, page_size: pageSize })),
    api.targets().catch(() => []),
    api.findingTools().catch(() => []),
    api.groups().catch(() => []),
  ]);
  const result = findingsResult ?? { items: [], total: 0 };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">All Findings</h1>
        <p className="text-sm text-muted-foreground">{result.total} findings across all targets</p>
      </div>
      <FindingsFilterBar targets={targets} tools={tools} groups={groups} />
      {findingsResult === null ? (
        <ErrorState
          description="The findings list couldn't be loaded from the API."
          action={<ReloadButton />}
        />
      ) : (
        <FindingsList findings={result.items} total={result.total} page={page} pageSize={pageSize} targets={targets} />
      )}
    </div>
  );
}
