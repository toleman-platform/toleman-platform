import { GroupBadge as GroupBadgeType } from "@/lib/api";

// Small colored pill for a target's group/tag (issue #61), used on the
// targets list, target detail page, and anywhere else a target's groups are
// surfaced. Uses the group's own `color` (set in Admin > Repo Groups)
// directly as inline style since the palette is user-chosen, not one of the
// design system's fixed variants.
export function GroupBadge({ group, onRemove }: { group: GroupBadgeType; onRemove?: () => void }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium text-white"
      style={{ backgroundColor: group.color }}
    >
      {group.name}
      {onRemove && (
        <button
          type="button"
          aria-label={`Remove ${group.name}`}
          onClick={onRemove}
          className="ml-0.5 leading-none opacity-80 hover:opacity-100"
        >
          ×
        </button>
      )}
    </span>
  );
}
