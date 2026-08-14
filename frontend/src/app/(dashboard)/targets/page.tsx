import { GitBranch } from "lucide-react";
import { api } from "@/lib/api";
import { ConnectGithubCard } from "@/components/connect-github-card";
import { AddTargetToggle } from "./add-target-toggle";
import { ConnectedRefresher } from "./connected-refresher";
import { GroupFilter } from "@/components/group-filter";
import { TargetsList } from "./targets-list";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";

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

  const [targetsResult, githubStatus, groups] = await Promise.all([
    settleOrNull(api.targets({ group_id })),
    api.githubAppStatus().catch(() => ({ app_configured: false, app_slug: null, installed: false, account_login: null })),
    api.groups().catch(() => []),
  ]);
  const targetsFailed = targetsResult === null;
  const targets = targetsResult ?? [];

  return (
    <div className="flex flex-col gap-8">
      <ConnectedRefresher />

      <div>
        <h1 className="text-2xl font-bold text-foreground">Repo Sync</h1>
        <p className="text-sm text-muted-foreground">Repositories under management</p>
      </div>

      <ConnectGithubCard />

      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium text-muted-foreground">
            Targets {targets.length > 0 && `(${targets.length})`}
          </h2>
          {groups.length > 0 && <GroupFilter groups={groups} />}
        </div>
        {targetsFailed && (
          <ErrorState description="The target list couldn't be loaded from the API." action={<ReloadButton />} />
        )}
        {!targetsFailed && targets.length > 0 && <TargetsList targets={targets} />}
        {!targetsFailed && targets.length === 0 && (
          <EmptyState
            icon={GitBranch}
            title={group_id ? "No targets in this group" : "No targets yet"}
            description={
              group_id
                ? "Add a target to this group, or clear the group filter."
                : githubStatus.installed
                  ? 'Click "Sync Repos Now" above, or add one manually below.'
                  : "Connect GitHub above, or add one manually below."
            }
          />
        )}
      </div>

      <AddTargetToggle defaultOpen={!githubStatus.installed && targets.length === 0} />
    </div>
  );
}
