import { api } from "@/lib/api";
import { AuditLogFilterBar, AuditLogList } from "@/components/features/logs";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { PageHeader } from "@/components/ui/page-header";
import { settleOrNull } from "@/std-lib";
// Plain module, not the "use client" component; a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";

// Page size is now a user preference read off the URL (25/50/100),
// defaulting to 25. See components/activity-pagination.tsx.

function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

export default async function AuditLogPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const event_type = firstValue(sp.event_type);
  const actor = firstValue(sp.actor);
  const date_from = firstValue(sp.date_from);
  const date_to = firstValue(sp.date_to);
  const pageRaw = firstValue(sp.page);
  const page = pageRaw && Number(pageRaw) > 0 ? Number(pageRaw) : 1;
  const pageSize = pageSizeFromParams(sp.page_size);

  const [auditResult, actors] = await Promise.all([
    settleOrNull(api.auditLog({ event_type, actor, date_from, date_to, page, page_size: pageSize })),
    api.auditActors().catch(() => []),
  ]);
  const result = auditResult ?? { items: [], total: 0 };

  // The count is omitted entirely when the read failed. Previously the header
  // rendered "... your data, 0 events, most recent first." directly above the
  // ErrorState below, so the page asserted a confident zero for data it had
  // not measured -- on a compliance surface, where "no events were recorded"
  // and "we couldn't reach the API" are very different claims.
  const description =
    auditResult === null
      ? "Every triage decision and scan run recorded against your data, most recent first."
      : `Every triage decision and scan run recorded against your data, ${result.total} events, most recent first.`;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Audit Log" description={description} />
      <AuditLogFilterBar actors={actors} />
      {auditResult === null ? (
        <ErrorState description="The audit log couldn't be loaded from the API." action={<ReloadButton />} />
      ) : (
        <AuditLogList events={result.items} total={result.total} page={page} pageSize={pageSize} />
      )}
    </div>
  );
}
