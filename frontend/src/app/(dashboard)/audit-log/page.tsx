import { api } from "@/lib/api";
import { AuditLogFilterBar } from "@/components/audit-log-filter-bar";
import { AuditLogList } from "@/components/audit-log-list";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";
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

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Audit Log</h1>
        <p className="text-sm text-muted-foreground">
          Every triage decision and scan run recorded against your data, {result.total} events, most recent first. A
          bulk triage action shows up as one grouped entry you can expand, not one card per finding.
        </p>
      </div>
      <AuditLogFilterBar actors={actors} />
      {auditResult === null ? (
        <ErrorState description="The audit log couldn't be loaded from the API." action={<ReloadButton />} />
      ) : (
        <AuditLogList events={result.items} total={result.total} page={page} pageSize={pageSize} />
      )}
    </div>
  );
}
