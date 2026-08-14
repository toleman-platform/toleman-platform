import { ScrollText } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";

export default async function AuditLogPage() {
  const events = await api.auditLog().catch(() => []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Audit Log</h1>
        <p className="text-sm text-muted-foreground">Triage decisions and scan runs, most recent first</p>
      </div>

      <div className="flex flex-col gap-2">
        {events.map((e, i) => (
          <Card key={i} className="border-border bg-card">
            <CardContent className="flex items-center justify-between px-4 py-2.5">
              <div>
                <div className="text-sm text-foreground">{e.summary}</div>
                {e.reason && <div className="text-xs text-muted-foreground">reason: {e.reason}</div>}
              </div>
              <div className="flex items-center gap-2 text-right">
                <Badge variant="outline" className="capitalize">
                  {e.type}
                </Badge>
                <span className="text-xs text-muted-foreground">{e.actor}</span>
                <span className="text-xs text-muted-foreground">{new Date(e.timestamp).toLocaleString()}</span>
              </div>
            </CardContent>
          </Card>
        ))}
        {events.length === 0 && (
          <EmptyState icon={ScrollText} title="No audit events yet" description="Triage decisions and scan runs will show up here as they happen." />
        )}
      </div>
    </div>
  );
}
