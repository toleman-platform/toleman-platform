import { GitBranch } from "lucide-react";
import { api } from "@/lib/api";
import { AddTargetToggle } from "./add-target-toggle";
import { ConnectedRefresher } from "./connected-refresher";
import { IntegrationSummary } from "./integration-summary";
import { GroupFilter } from "@/components/features/targets";
import { TargetsFilterBar } from "./targets-filter-bar";
import { TargetsList } from "./targets-list";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { PageHeader } from "@/components/ui/page-header";
import { settleOrNull } from "@/std-lib";

function firstValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

export default async function TargetsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const groupIdRaw = firstValue(sp.group_id);
  const group_id = groupIdRaw ? Number(groupIdRaw) : undefined;

  // Issue #174: scan history + open-finding counts alongside the inventory,
  // so a Repo Sync card can say which repos actually need attention instead
  // of just naming them. Both summaries degrade to {} on failure, a card
  // then renders without its metadata line rather than failing the page.
  const [targetsResult, githubStatus, groupsList, scanSummaryData, targetSummaryData, me] = await Promise.all([
    settleOrNull(api.targets({ group_id })),
    api.githubAppStatus().catch(() => ({ app_configured: false, app_slug: null, installed: false, account_login: null })),
    api.groups().catch(() => []),
    api.scanSummary().catch(() => ({})),
    api.targetsSummary().catch(() => ({})),
    // (#356) The add-target form's empty-workspace state differs by role:
    // GET /api/workspaces is scoped by accessible_workspace_ids, so an empty
    // list means "none exist" to an admin and "you're a member of none" to
    // everyone else, and only an admin can act on it (create_workspace is
    // admin-gated). Resolved here, in the render that already round-trips to
    // the API five times, rather than by the form fetching /api/auth/me for
    // itself: a client-side fetch would race the workspace list and flash a
    // membership claim at the one person who could actually fix the
    // situation. settleOrNull, not .catch(() => ...), because "couldn't
    // determine the role" has to stay distinct from "not an admin" -- see
    // NewTargetForm's isAdmin prop.
    settleOrNull(api.me()),
  ]);
  const targetsFailed = targetsResult === null;
  const targetsList = targetsResult ?? [];
  const isAdmin = me === null ? null : me.role === "admin";

  return (
    <div className="flex flex-col gap-6">
      <ConnectedRefresher />

      <PageHeader
        title="Targets"
        description="Repositories under management"
      />

      {/* Issue #125: integration admin config (connect button, webhook status,
          org sync controls) collapsed to a one-line summary by default so it
          doesn't push the actual target inventory below the fold, expand to
          reach the full ConnectGithubCard. */}
      <IntegrationSummary
        installed={githubStatus.installed}
        accountLogin={githubStatus.account_login}
        targetsCount={targetsList.length}
        defaultOpen={!githubStatus.installed && targetsList.length === 0}
      />

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium text-muted-foreground">
            Targets {targetsList.length > 0 && `(${targetsList.length})`}
          </h2>
          {groupsList.length > 0 && <GroupFilter groups={groupsList} />}
        </div>
        <TargetsFilterBar />
        {targetsFailed && (
          <ErrorState description="The target list couldn't be loaded from the API." action={<ReloadButton />} />
        )}
        {!targetsFailed && targetsList.length > 0 && (
          <TargetsList targets={targetsList} scanSummary={scanSummaryData} targetSummary={targetSummaryData} />
        )}
        {!targetsFailed && targetsList.length === 0 && (
          <EmptyState
            icon={GitBranch}
            title={group_id ? "No targets in this group" : "No targets yet"}
            description={
              group_id
                ? "Add a target to this group, or clear the group filter."
                : githubStatus.installed
                  ? 'Expand "GitHub App connected" above to sync repos now, or add one manually below.'
                  : "Expand the connection summary above to connect GitHub, or add one manually below."
            }
          />
        )}
      </div>

      <AddTargetToggle defaultOpen={!githubStatus.installed && targetsList.length === 0} isAdmin={isAdmin} />

    </div>
  );
}
