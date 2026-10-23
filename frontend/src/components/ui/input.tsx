import * as React from 'react'

import { cn } from '@/lib/utils'

function Input({ className, type, ...props }: React.ComponentProps<'input'>) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        // `dark:bg-input/30` and `dark:aria-invalid:ring-destructive/40`
        // (below) removed: dead code, matching a `.dark` class this app
        // never sets. See globals.css for the variant's own history.
        'file:text-foreground placeholder:text-muted-foreground border-input h-10 w-full min-w-0 rounded-lg border bg-transparent px-3.5 py-1 text-base transition-[color,box-shadow,border-color] duration-200 outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm',
        'focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]',
        'aria-invalid:ring-destructive/20 aria-invalid:border-destructive',
        className,
      )}
      {...props}
    />
  )
}

export { Input }
