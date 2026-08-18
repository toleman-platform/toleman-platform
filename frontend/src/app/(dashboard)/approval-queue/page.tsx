"use client";

import { useEffect, useState } from "react";
import { api, AuthUser } from "@/lib/api";
import { ApprovalQueue } from "@/app/(dashboard)/admin/approval-queue";
import { EmptyState } from "@/components/ui/empty-state";
import { ShieldOff } from "lucide-react";

// Nav restructure (IA review, #224): Approval Queue used to be reachable
// only as a tab inside /admin -- and /admin's own sidebar link is
// `adminOnly`, so a security_engineer (who this page's own role check has
// always permitted) had no nav path to it at all. They could still open
// /admin by typing the URL, since nothing backend-enforced ever blocked the
// route itself, but nothing pointed them there. Promoting this to its own
// route under Triage is a deliberate widening of *navigability*, not of
// *access* -- the role check below is copied verbatim from what
// admin/page.tsx already enforced (admin or security_engineer), not
// loosened.
const ALLOWED_ROLES = ["admin", "security_engineer"];

export default function ApprovalQueuePage() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setChecked(true));
  }, []);

  if (!checked) return null;

  if (!user || !ALLOWED_ROLES.includes(user.role)) {
    return (
      <EmptyState
        icon={ShieldOff}
        title="Security review access required"
        description="Approving or rejecting an ignore request needs the security_engineer role or above."
      />
    );
  }

  return <ApprovalQueue />;
}
