import { api } from "@/lib/api";
import { FindingsFilterBar } from "@/components/findings-filter-bar";
import { FindingsList } from "@/components/findings-list";

const PAGE_SIZE = 25;

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

  const [result, targets, tools, groups] = await Promise.all([
    api
      .findings({ severity, tool, state, search, target_id, group_id, page, page_size: PAGE_SIZE })
      .catch(() => ({ items: [], total: 0 })),
    api.targets().catch(() => []),
    api.findingTools().catch(() => []),
    api.groups().catch(() => []),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">All Findings</h1>
        <p className="text-sm text-muted-foreground">{result.total} findings across all targets</p>
      </div>
      <FindingsFilterBar targets={targets} tools={tools} groups={groups} />
      <FindingsList findings={result.items} total={result.total} page={page} pageSize={PAGE_SIZE} targets={targets} />
    </div>
  );
}
