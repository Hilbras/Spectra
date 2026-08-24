import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/components/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-gold-500 text-black hover:bg-gold-600 shadow-md shadow-gold-500/20',
        gold: 'bg-gradient-to-r from-gold-400 to-gold-600 text-black hover:from-gold-500 hover:to-gold-700 shadow-lg shadow-gold-500/25',
        ghost: 'hover:bg-accent hover:text-foreground',
        outline: 'border border-border bg-background hover:bg-accent hover:text-foreground',
        destructive: 'bg-error text-error-fg hover:bg-error/90 shadow-md shadow-error/20',
        secondary: 'bg-muted text-muted-foreground hover:bg-muted/80',
        glass: 'glass text-foreground hover:bg-white/20 dark:hover:bg-white/5',
      },
      size: {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-11 px-6 text-base',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      />
    )
  }
)
Button.displayName = 'Button'

export { Button, buttonVariants }
