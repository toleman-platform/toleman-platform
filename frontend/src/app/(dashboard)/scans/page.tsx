import Link from "next/link";
import { Scan } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";
import { ScanButtons } from "../targets/[id]/scan-buttons";

export default async function OnDemandScanPage() {
  const targetsResult = await settleOrNull(api.targets());
  const targetsFailed = targetsResult === null;
  const targets = targetsResult ?? [];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">On-Demand Scan</h1>
        <p className="text-sm text-muted-foreground">Trigger a native scan against any target now</p>
      </div>

      <div className="flex flex-col gap-2">
        {targets.map((t) => (
          <Card key={t.id} interactive className="border-border bg-card">
            <CardContent
              className="flex items-center justify-between px-4"
              style={{ paddingTop: "var(--density-row-py)", paddingBottom: "var(--density-row-py)" }}
            >
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
        {targetsFailed && (
          <ErrorState description="The target list couldn't be loaded from the API." action={<ReloadButton />} />
        )}
        {!targetsFailed && targets.length === 0 && (
          <EmptyState
            icon={Scan}
            title="No targets yet"
            description="Add a repository in Repo Sync before you can trigger a scan."
            action={
              <Button size="sm" asChild>
                <Link href="/targets">Go to Repo Sync</Link>
              </Button>
            }
          />
        )}
      </div>
    </div>
  );
}
