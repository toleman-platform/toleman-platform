/**
 * Shared admin-destination visibility gate. Null/undefined means the role could not be
 * read; callers must communicate that uncertainty rather than presenting a shortened
 * list as complete.
 */
export function canSeeAdminOnly(role: string | null | undefined): boolean {
  return role === "admin" || role === "security_engineer";
}
