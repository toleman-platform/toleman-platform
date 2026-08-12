import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { ScanButtons } from "../targets/[id]/scan-buttons";

export default async function OnDemandScanPage() {
  const targets = await api.targets().catch(() => []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">On-Demand Scan</h1>
        <p className="text-sm text-muted-foreground">Trigger a native scan against any target now</p>
      </div>

      <div className="flex flex-col gap-2">
        {targets.map((t) => (
          <Card key={t.id} className="border-border bg-card">
            <CardContent className="flex items-center justify-between px-4 py-3">
              <div>
                <div className="font-medium text-foreground">{t.name}</div>
                <div className="text-xs text-muted-foreground">
                  {t.repo_url} · {t.label} · branch {t.default_branch}
                </div>
              </div>
              <ScanButtons targetId={t.id} />
            </CardContent>
          </Card>
        ))}
        {targets.length === 0 && <p className="text-sm text-muted-foreground">No targets yet — add one in Repo Sync.</p>}
      </div>
    </div>
  );
}
