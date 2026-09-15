import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  // core lows: `transition-all` was animating every animatable property on
  // this element, not just the ones any variant below actually changes
  // (background-color, border-color, color, box-shadow via the
  // focus-visible ring). That's needless paint work on every hover/focus of
  // the most-instantiated element in the app, and it silently picks up
  // `outline-color`/anything a future variant adds -- naming the properties
  // is what makes the transition's scope an intentional decision instead of
  // an accident. `motion-reduce:transition-none` disables it outright under
  // prefers-reduced-motion, same guard drawer.tsx already uses for its
  // slide/fade.
  // `dark:` utilities removed here (was `dark:aria-invalid:ring-destructive/40`
  // below, `dark:focus-visible:ring-destructive/40 dark:bg-destructive/80` on
  // the destructive variant): dead code, matching a `.dark` class this app
  // never sets, and since removed along with the variant declaration itself;
  // globals.css carries that history and the order the two had to happen in.
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-[color,background-color,border-color,box-shadow] motion-reduce:transition-none disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary/90',
        destructive:
          'bg-destructive text-destructive-foreground hover:bg-destructive/90 focus-visible:ring-destructive/20',
        // `bg-background` was the defect, not the `dark:` utilities that used
        // to sit beside it. The page background IS the surface a card is
        // drawn on top of, so an outline button inside a Card -- which is
        // where nearly all of them are -- was painted darker than its own
        // ground (0.0090 vs --card's 0.0142 in dark; the same inversion the
        // other way round in light, 0.9284 under #ffffff) and read as a hole
        // punched in the card rather than a control resting on it. `bg-control`
        // is the ground of a control, valued per theme so it is never darker
        // than any surface it can sit on; `bg-control-hover` is picked per
        // theme too, so a hovered button never sinks below the page around it
        // -- the old `hover:bg-accent` (0.0191 in dark) dropped it back under
        // its own resting ground. `text-foreground` stops an outline button
        // inheriting a muted colour from whatever block it is nested in, now
        // that it has a ground of its own. Numbers in globals.css.
        //
        // `border-input` colours the edge with the control-boundary token
        // rather than the surface hairline, so the button's outline clears
        // the 3:1 that a control's boundary needs; in light, where a white
        // control cannot be lifted above a white card at all, that edge is
        // what carries the separation.
        outline:
          'border border-input bg-control text-foreground shadow-xs hover:bg-control-hover',
        secondary:
          'bg-secondary text-secondary-foreground hover:bg-secondary/80',
        ghost:
          'hover:bg-accent hover:text-accent-foreground',
        link: 'text-accent-strong underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 py-2 has-[>svg]:px-3',
        sm: 'h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5',
        lg: 'h-10 rounded-md px-6 has-[>svg]:px-4',
        icon: 'size-9',
        'icon-sm': 'size-8',
        'icon-lg': 'size-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<'button'> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : 'button'

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
