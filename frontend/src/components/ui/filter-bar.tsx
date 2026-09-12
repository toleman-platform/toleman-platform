import * as React from "react";
import { Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Icon as IconWrapper } from "@/components/ui/icon";

export interface FilterPillItem {
  id: string;
  label: string;
  value: string;
  onRemove: () => void;
}

export interface FilterBarProps extends React.HTMLAttributes<HTMLDivElement> {
  searchValue?: string;
  onSearchChange?: (val: string) => void;
  searchPlaceholder?: string;
  filters?: React.ReactNode;
  activePills?: FilterPillItem[];
  onClearAllPills?: () => void;
  actions?: React.ReactNode;
}

/**
 * Standardized Filter & Search Bar component.
 * 
 * Provides unified search inputs with clear buttons, custom filter dropdown slots,
 * removable active filter pills, and a clear-all action.
 */
export function FilterBar({
  searchValue = "",
  onSearchChange,
  searchPlaceholder = "Search...",
  filters,
  activePills = [],
  onClearAllPills,
  actions,
  className,
  ...props
}: FilterBarProps) {
  return (
    <div className={cn("space-y-2.5", className)} {...props}>
      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-1 items-center gap-2">
          {onSearchChange && (
            <div className="relative flex-1 max-w-sm">
              <IconWrapper icon={Search} size="sm" tone="muted" className="absolute left-2.5 top-1/2 -translate-y-1/2" />
              <Input
                type="search"
                value={searchValue}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder={searchPlaceholder}
                className="pl-8 text-xs"
              />
              {searchValue && (
                <button
                  type="button"
                  onClick={() => onSearchChange("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  aria-label="Clear search"
                >
                  <IconWrapper icon={X} size="xs" />
                </button>
              )}
            </div>
          )}
          {filters}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>

      {activePills && activePills.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Active filters:</span>
          {activePills.map((pill) => (
            <span
              key={pill.id}
              className="inline-flex items-center gap-1 rounded-full border border-border bg-secondary px-2.5 py-0.5 text-xs text-foreground"
            >
              <span className="text-muted-foreground">{pill.label}:</span>
              <span className="font-medium">{pill.value}</span>
              <button
                type="button"
                onClick={pill.onRemove}
                className="ml-0.5 text-muted-foreground hover:text-destructive"
                aria-label={`Remove filter ${pill.label} ${pill.value}`}
              >
                <IconWrapper icon={X} size="xs" />
              </button>
            </span>
          ))}
          {onClearAllPills && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onClearAllPills}
              className="h-6 text-[11px] text-muted-foreground hover:text-foreground px-2"
            >
              Clear all
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
