import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default async function GithubOrgLogsPage() {
  const events = await api.orgActivity().catch(() => []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">GitHub Org Logs</h1>
        <p className="text-sm text-muted-foreground">
          Recent commit activity across every integrated target. A true GitHub org audit log needs an
          Enterprise/paid-org scope not available for personal accounts, so this shows real per-repo
          commit activity instead of fabricating org-level events.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        {events.map((e, i) => (
          <Card key={i} className="border-border bg-card">
            <CardContent className="flex items-center justify-between px-4 py-2.5">
              <div>
                <a href={e.url} target="_blank" rel="noreferrer" className="text-sm text-foreground hover:underline">
                  {e.message}
                </a>
                <div className="text-xs text-muted-foreground">
                  {e.author} · {e.sha}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline">{e.target}</Badge>
                <span className="text-xs text-muted-foreground">{e.date ? new Date(e.date).toLocaleString() : ""}</span>
              </div>
            </CardContent>
          </Card>
        ))}
        {events.length === 0 && <p className="text-sm text-muted-foreground">No activity found.</p>}
      </div>
    </div>
  );
}
