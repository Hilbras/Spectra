import { ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/components/lib/utils'

interface PerspectiveCardProps {
  children: ReactNode
  className?: string
  tilt?: boolean
}

export function PerspectiveCard({ children, className = '', tilt = true }: PerspectiveCardProps) {
  const mouseHandle = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!tilt) return
    const card = e.currentTarget
    const rect = card.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    const centerX = rect.width / 2
    const centerY = rect.height / 2
    const rotateX = ((y - centerY) / centerY) * -5
    const rotateY = ((x - centerX) / centerX) * 5
    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`
  }

  const mouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!tilt) return
    e.currentTarget.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)'
  }

  return (
    <motion.div
      className={cn('will-change-transform', className)}
      onMouseMove={mouseHandle}
      onMouseLeave={mouseLeave}
      whileHover={{ scale: 1.02 }}
      transition={{ type: 'spring', stiffness: 300, damping: 25 }}
    >
      {children}
    </motion.div>
  )
}
