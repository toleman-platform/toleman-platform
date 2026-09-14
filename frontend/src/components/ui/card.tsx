import * as React from 'react'

import { cn } from '@/lib/utils'

function Card({
  className,
  interactive = false,
  ...props
}: React.ComponentProps<'div'> & { interactive?: boolean }) {
  return (
    <div
      data-slot="card"
      className={cn(
        'bg-card text-card-foreground flex flex-col gap-6 rounded-xl border py-6 shadow-sm',
        interactive && 'interactive-surface',
        className,
      )}
      {...props}
    />
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        '@container/card-header grid auto-rows-min grid-rows-[auto_auto] items-start gap-2 px-6 has-data-[slot=card-action]:grid-cols-[1fr_auto] [.border-b]:pb-6',
        className,
      )}
      {...props}
    />
  )
}

function CardTitle({
  className,
  // core lows: this rendered a <div>, so every page built from cards --
  // dashboard widgets, the design-system showcase -- had no heading in its
  // accessibility tree at all. A screen reader's "jump to next heading"
  // command is how sighted users' F5 skim of a page translates for anyone
  // navigating by ear, and it found nothing here.
  //
  // Defaults to h2, not h1 or h3: PageHeader (page-header.tsx) already
  // renders the page's own h1, and several Card bodies in this codebase
  // (design-system/page.tsx) nest their own literal <h3> sub-section
  // headings one level below their CardTitle -- so the Card itself sits at
  // h2 in that hierarchy. `as` exists for the rare page that genuinely needs
  // a different level rather than force everyone onto one.
  as: Comp = 'h2',
  ...props
}: React.ComponentProps<'h2'> & { as?: React.ElementType }) {
  return (
    <Comp
      data-slot="card-title"
      className={cn('leading-none font-semibold', className)}
      {...props}
    />
  )
}

function CardDescription({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-description"
      className={cn('text-muted-foreground text-sm', className)}
      {...props}
    />
  )
}

function CardAction({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-action"
      className={cn(
        'col-start-2 row-span-2 row-start-1 self-start justify-self-end',
        className,
      )}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-content"
      className={cn('px-6', className)}
      {...props}
    />
  )
}

function CardFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-footer"
      className={cn('flex items-center px-6 [.border-t]:pt-6', className)}
      {...props}
    />
  )
}

export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
}
