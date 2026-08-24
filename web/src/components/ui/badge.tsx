import * as React from 'react'
import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/components/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default:  'border-transparent bg-gold-500 text-black',
        secondary:'border-transparent bg-muted text-muted-foreground',
        destructive:'border-transparent bg-error text-error-fg',
        outline:  'border-border text-foreground',
        critical: 'border-transparent bg-critical/15 text-critical',
        high:     'border-transparent bg-high/15 text-high',
        medium:   'border-transparent bg-medium/15 text-medium',
        low:      'border-transparent bg-low/15 text-low',
        success:  'border-transparent bg-success/15 text-success',
        info:     'border-transparent bg-info/15 text-info',
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
