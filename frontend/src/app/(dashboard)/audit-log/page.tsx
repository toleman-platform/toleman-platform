import Link from "next/link";
import { api } from "@/lib/api";
import { AuditLogFilterBar, AuditLogList } from "@/components/features/logs";
import { PageHeader } from "@/components/ui/page-header";
import { PartialFailureBanner } from "@/components/ui/partial-failure-banner";
import { AlertBanner } from "@/components/ui/alert-banner";
import { Button } from "@/components/ui/button";
import { settleOrNull, settledOr } from "@/std-lib";
// Plain module, not the "use client" component; a Server Component
// cannot call a function exported from a client module.
import { pageSizeFromParams } from "@/lib/pagination";

// Page size is now a user preference read off the URL (25/50/100),
// defaulting to 25. See components/ui/activity-pagination.tsx.

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

  const [auditResult, [actors, actorsFailed], me] = await Promise.all([
    settleOrNull(api.auditLog({ event_type, actor, date_from, date_to, page, page_size: pageSize })),
    // settledOr, not `.catch(() => [])`: an empty actor list and an actor list
    // that could not be fetched look identical in the filter's <select>, and
    // the second one silently narrows what an auditor believes happened -- the
    // "All actors" option stops being all actors, with nothing saying so.
    // Secondary to the log itself, so it degrades the page rather than failing
    // it, but the boolean has to survive and be rendered (std-lib/async.ts).
    settledOr(api.auditActors(), [] as string[]),
    // Whether to render a working link to the Security Log below (admin-
    // only, see AlertBanner further down). settleOrNull, not .catch(() =>
    // null): "not an admin" and "couldn't tell" both suppress the link, but
    // only the first is actually a claim about the viewer's role, so the two
    // must stay distinguishable at the call site even though they render
    // the same way here (same reasoning as targets/page.tsx's isAdmin).
    settleOrNull(api.me()),
  ]);
  const result = auditResult ?? { items: [], total: 0 };
  const isAdmin = me?.role === "admin";

  // The count is omitted entirely when the read failed. Previously the header
  // rendered "... your data, 0 events, most recent first." unconditionally,
  // so the page asserted a confident zero for data it had not measured -- on
  // a compliance surface, where "no events were recorded" and "we couldn't
  // reach the API" are very different claims.
  //
  // "MCP/API token" is named explicitly, not folded into "scan run": the
  // event-type facet below already lists it as its own filter option, and
  // this feed genuinely includes it (audit.py's third block) -- a
  // description that only mentions triage and scans would itself be an
  // audit trail understating its own scope, the exact failure this page's
  // missing-auth-events gap (see the AlertBanner below) was flagged for.
  const description =
    auditResult === null
      ? "Every triage decision, scan run, and MCP/API token action recorded against your data, most recent first."
      : `Every triage decision, scan run, and MCP/API token action recorded against your data, ${result.total} events, most recent first.`;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Audit Log" description={description} />

      <PartialFailureBanner
        sources={[
          {
            label: "Actor list",
            failed: actorsFailed,
            consequence: "the actor filter is empty, so filtering by user is unavailable",
          },
        ]}
      />

      {/* This is a findings-and-scan trail, not a full activity record --
          it deliberately says so rather than let "Audit Log" imply
          completeness it doesn't have. Logins, permission changes, and
          target lifecycle events are real DB rows (AuthAuditLog) with their
          own actor/IP/timestamp, just not these ones: they're written by a
          separate table behind a stricter, admin-only gate (require_admin
          on GET /api/audit/security-log, vs. this page's login_required),
          so folding them into this feed would hand every authenticated user
          -- not just admins -- visibility into who else logged in, from
          where, and whose role changed. Two unlinked pages is the failure
          mode SOC 2 / ISO 27001 auditors flag, so the fix here is the link,
          not a merge that would also change who can see what. */}
      <AlertBanner
        tone="info"
        title="Sign-ins and permission changes aren't in this trail"
        action={
          isAdmin ? (
            <Button size="sm" variant="outline" asChild>
              <Link href="/admin?tab=security-log">Open Security Log</Link>
            </Button>
          ) : undefined
        }
      >
        Logins, logouts, password and role changes, and target lifecycle events (deactivated,
        reactivated, deleted) are recorded separately in the Security Log, under Admin &gt; Access
        &mdash; visible to admins only.
      </AlertBanner>

      <AuditLogFilterBar actors={actors} />
      {/* `failed` (not a page-level ternary around ErrorState/AuditLogList) is
          what makes "no events" and "we couldn't load events" structurally
          unable to converge -- see AuditLogList's own docstring on the prop. */}
      <AuditLogList
        events={result.items}
        total={result.total}
        page={page}
        pageSize={pageSize}
        failed={auditResult === null}
      />
    </div>
  );
}
