import Link from "next/link";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { ConnectGithubCard } from "@/components/connect-github-card";
import { AddTargetToggle } from "./add-target-toggle";
import { ConnectedRefresher } from "./connected-refresher";
import { GroupFilter } from "@/components/group-filter";
import { GroupBadge } from "@/components/group-badge";

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

  const [targets, githubStatus, groups] = await Promise.all([
    api.targets({ group_id }).catch(() => []),
    api.githubAppStatus().catch(() => ({ app_configured: false, app_slug: null, installed: false, account_login: null })),
    api.groups().catch(() => []),
  ]);

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
        {targets.map((t) => (
          <Link key={t.id} href={`/targets/${t.id}`}>
            <Card className="border-border bg-card transition-colors hover:border-primary/40">
              <CardContent className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="font-medium text-foreground">{t.name}</div>
                  <div className="text-xs text-muted-foreground">{t.repo_url}</div>
                  {t.groups.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {t.groups.map((g) => (
                        <GroupBadge key={g.id} group={g} />
                      ))}
                    </div>
                  )}
                </div>
                <span className="text-xs text-muted-foreground">
                  {t.label} · weight {t.criticality_weight}
                </span>
              </CardContent>
            </Card>
          </Link>
        ))}
        {targets.length === 0 && (
          <p className="text-sm text-muted-foreground">
            {group_id
              ? "No targets in this group."
              : githubStatus.installed
                ? "No targets yet. Click \"Sync Repos Now\" above, or add one manually below."
                : "No targets yet. Connect GitHub above, or add one manually below."}
          </p>
        )}
      </div>

      <AddTargetToggle defaultOpen={!githubStatus.installed && targets.length === 0} />
    </div>
  );
}
