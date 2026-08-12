import Link from "next/link";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { ConnectGithubCard } from "@/components/connect-github-card";
import { AddTargetToggle } from "./add-target-toggle";
import { ConnectedRefresher } from "./connected-refresher";

export default async function TargetsPage() {
  const [targets, githubStatus] = await Promise.all([
    api.targets().catch(() => []),
    api.githubAppStatus().catch(() => ({ app_configured: false, app_slug: null, installed: false, account_login: null })),
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
        </div>
        {targets.map((t) => (
          <Link key={t.id} href={`/targets/${t.id}`}>
            <Card className="border-border bg-card transition-colors hover:border-primary/40">
              <CardContent className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="font-medium text-foreground">{t.name}</div>
                  <div className="text-xs text-muted-foreground">{t.repo_url}</div>
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
            No targets yet. {githubStatus.installed ? "Click \"Sync Repos Now\" above, or add one manually below." : "Connect GitHub above, or add one manually below."}
          </p>
        )}
      </div>

      <AddTargetToggle defaultOpen={!githubStatus.installed && targets.length === 0} />
    </div>
  );
}
