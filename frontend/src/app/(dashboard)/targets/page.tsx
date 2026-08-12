import Link from "next/link";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { NewTargetForm } from "./new-target-form";
import { ConnectGithubCard } from "@/components/connect-github-card";

export default async function TargetsPage() {
  const targets = await api.targets().catch(() => []);

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Repo Sync</h1>
        <p className="text-sm text-muted-foreground">Repositories under management</p>
      </div>

      <ConnectGithubCard />

      <NewTargetForm />

      <div className="flex flex-col gap-2">
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
        {targets.length === 0 && <p className="text-sm text-muted-foreground">No targets yet.</p>}
      </div>
    </div>
  );
}
