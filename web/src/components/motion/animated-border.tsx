import { ReactNode } from 'react'
import { cn } from '@/components/lib/utils'

interface AnimatedBorderProps {
  children: ReactNode
  className?: string
  borderWidth?: number
  duration?: number
}

export function AnimatedBorder({
  children,
  className = '',
  borderWidth = 1.5,
  duration = 4,
}: AnimatedBorderProps) {
  return (
    <div
      className={cn('relative rounded-xl p-[1px] overflow-hidden', className)}
      style={{ borderWidth }}
    >
      <div
        className="absolute inset-0 z-0"
        style={{
          background: 'conic-gradient(from 0deg, transparent, var(--color-gold-500), transparent, var(--color-gold-300), transparent)',
          animation: `spin ${duration}s linear infinite`,
        }}
      />
      <div className="relative z-10 rounded-[inherit] bg-card">
        {children}
      </div>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
