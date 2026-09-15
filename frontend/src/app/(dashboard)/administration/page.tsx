import Link from "next/link";
import { Building2, Settings, UserCog, type LucideIcon } from "lucide-react";
import { api } from "@/lib/api";
import { canSeeAdminOnly } from "@/lib/roles";
import { settleOrNull } from "@/std-lib";
import { PageHeader } from "@/components/ui/page-header";
import { AlertBanner } from "@/components/ui/alert-banner";
import { ReloadButton } from "@/components/reload-button";
import { ListRow } from "@/components/ui/list-row";

type Destination = {
  href: string;
  label: string;
  /** What the destination is for. Taken from each page's own header copy so
   *  this index never describes a surface differently from the surface. */
  description: string;
  icon: LucideIcon;
  /** Must stay identical to the matching entry in components/sidebar.tsx;
   *  the two lists gate on the same roles and drifting apart would offer a
   *  link the sidebar deliberately hides. */
  adminOnly?: boolean;
};

const DESTINATIONS: Destination[] = [
  {
    href: "/settings",
    label: "Settings",
    description: "Your profile, notification preferences, API tokens, and per-target configuration.",
    icon: Settings,
  },
  {
    href: "/workspaces",
    label: "Workspaces",
    description:
      "Create and rename workspaces, manage each one's CI-ingestion API key, and assign per-workspace roles.",
    icon: Building2,
    adminOnly: true,
  },
  {
    href: "/admin",
    label: "Control Plane",
    description: "Users and access, global integrations, scanner health and the tool marketplace, and scan scheduling.",
    icon: UserCog,
    adminOnly: true,
  },
];

/**
 * Index for the sidebar's Administration group.
 *
 * The group's destinations are configuration surfaces that change how this
 * instance behaves, as opposed to the Audit Trails group's read-only
 * evidence. Role filtering below mirrors the sidebar's exactly.
 */
export default async function AdministrationPage() {
  // settleOrNull, not `.catch(() => null)`: "this account is not an admin"
  // and "the role could not be read" both hide the same links, but only the
  // first is a claim about the viewer, so the two stay distinguishable here
  // and the second is said out loud rather than rendered as a short list
  // that looks authoritative.
  const me = await settleOrNull(api.me());
  const canSee = canSeeAdminOnly(me?.role);
  const destinations = DESTINATIONS.filter((d) => !d.adminOnly || canSee);
  const roleUnknown = me === null;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Administration"
        description="Configuration for this instance: your own settings, workspace management, and the platform control plane."
      />

      {roleUnknown && (
        <AlertBanner tone="warning" title="Some destinations may be missing">
          <div className="flex flex-col items-start gap-2">
            <span>
              Your account could not be read, so anything restricted to administrators and security
              engineers is not listed here. You may simply be signed out.
            </span>
            <ReloadButton />
          </div>
        </AlertBanner>
      )}

      <ul className="flex flex-col gap-2">
        {destinations.map((d) => (
          <li key={d.href}>
            <Link
              href={d.href}
              className="block rounded-xl outline-none focus-visible:ring-ring/50 focus-visible:ring-[3px]"
            >
              <ListRow interactive>
                <div className="flex items-start gap-3">
                  <d.icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground">{d.label}</span>
                      {d.adminOnly && (
                        <span className="rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider text-warning">
                          ADMIN
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">{d.description}</p>
                  </div>
                </div>
              </ListRow>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
