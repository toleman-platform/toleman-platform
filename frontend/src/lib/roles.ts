/**
 * Who may see the destinations marked admin-only.
 *
 * This lived in two places -- the sidebar's nav filter and the Administration
 * index -- as the same hand-written comparison, with a comment on one of them
 * asking that they be kept in sync and nothing to make that happen. A role
 * gate that drifts does not fail loudly: one surface starts listing a
 * destination the other hides, and the disagreement is only visible to
 * whoever happens to hold that role.
 *
 * `null`/`undefined` means the role could not be read, which is not the same
 * claim as "this user is not an administrator". Callers are expected to say
 * so rather than rendering a short list as though it were complete.
 */
export function canSeeAdminOnly(role: string | null | undefined): boolean {
  return role === "admin" || role === "security_engineer";
}
