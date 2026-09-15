"use client";

import { ArrowUp, ArrowDown, X, GripVertical } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// Shared chrome around every dashboard widget (issue #69): title/icon in
// view mode, plus move-up/move-down/remove controls in edit mode. Move
// buttons are a deliberate, real reorder implementation (not a stand-in
// for drag-and-drop) since they're simpler to get genuinely working than
// a drag library integration and are just as functional for reordering a
// short widget list.
export function WidgetShell({
  icon: Icon,
  title,
  editMode,
  isFirst,
  isLast,
  onMoveUp,
  onMoveDown,
  onRemove,
  colSpanClass = "",
  hiddenFromView = false,
  children,
}: {
  icon: React.ElementType;
  title: string;
  editMode: boolean;
  isFirst: boolean;
  isLast: boolean;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onRemove: () => void;
  colSpanClass?: string;
  /** This widget is turned off in the user's widget menu. Only ever true in
   * edit mode -- the board drops hidden widgets entirely in view mode -- so
   * that someone rearranging their layout can still see and move every
   * widget it contains, and can tell which ones they will not see
   * afterwards. */
  hiddenFromView?: boolean;
  children: React.ReactNode;
}) {
  return (
    <Card
      className={`border-border bg-card ${colSpanClass} ${editMode ? "ring-1 ring-primary/30" : ""} ${
        hiddenFromView ? "opacity-60" : ""
      }`}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium text-foreground">
            {editMode && <GripVertical className="h-4 w-4 text-muted-foreground" aria-hidden="true" />}
            <Icon className="h-4 w-4 text-accent-strong" />
            {title}
            {hiddenFromView && (
              <Badge variant="outline" className="px-1.5 py-0 text-[10px] font-normal text-muted-foreground">
                Hidden
              </Badge>
            )}
          </CardTitle>
          {editMode && (
            <div className="flex items-center gap-1">
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Move ${title} up`}
                disabled={isFirst}
                onClick={onMoveUp}
              >
                <ArrowUp className="h-3.5 w-3.5" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Move ${title} down`}
                disabled={isLast}
                onClick={onMoveDown}
              >
                <ArrowDown className="h-3.5 w-3.5" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove ${title}`}
                className="text-destructive hover:text-destructive"
                onClick={onRemove}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}
