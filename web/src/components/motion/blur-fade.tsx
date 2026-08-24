import { type ReactNode } from 'react'
import { motion } from 'framer-motion'

interface BlurFadeProps {
  children: ReactNode
  className?: string
  delay?: number
  duration?: number
  y?: number
  blur?: number
}

export function BlurFade({
  children,
  className = '',
  delay = 0,
  duration = 0.5,
  y = 16,
  blur = 8,
}: BlurFadeProps) {
  return (
    <motion.div
      initial={{ opacity: 0, filter: `blur(${blur}px)`, y }}
      animate={{ opacity: 1, filter: 'blur(0px)', y: 0 }}
      transition={{
        duration,
        delay,
        ease: [0.25, 0.46, 0.45, 0.94] as const,
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}
