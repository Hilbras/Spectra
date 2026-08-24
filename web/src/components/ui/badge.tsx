import * as React from 'react'
import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/components/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-gold-500 text-black',
        secondary: 'border-transparent bg-muted text-muted-foreground',
        destructive: 'border-transparent bg-red-500 text-white',
        outline: 'border-border text-foreground',
        critical: 'border-transparent bg-red-500/15 text-red-600 dark:text-red-400',
        high: 'border-transparent bg-orange-500/15 text-orange-600 dark:text-orange-400',
        medium: 'border-transparent bg-yellow-500/15 text-yellow-700 dark:text-yellow-400',
        low: 'border-transparent bg-blue-500/15 text-blue-600 dark:text-blue-400',
        success: 'border-transparent bg-green-500/15 text-green-700 dark:text-green-400',
        info: 'border-transparent bg-gold-500/15 text-gold-700 dark:text-gold-400',
      },
    },
    defaultVariants: { variant: 'default' },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
