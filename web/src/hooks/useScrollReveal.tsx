import { useEffect, useRef, useState } from 'react'
import { motion, useAnimation, useInView } from 'framer-motion'

interface UseScrollRevealOptions {
  threshold?: number
  rootMargin?: string
  initial?: Record<string, unknown>
  animate?: Record<string, unknown>
}

const defaultInitial = { opacity: 0, y: 24, filter: 'blur(8px)' }
const defaultAnimate = { opacity: 1, y: 0, filter: 'blur(0px)' }
const defaultTransition = { duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] as const }

export function useScrollReveal(options: UseScrollRevealOptions = {}) {
  const ref = useRef<HTMLDivElement>(null)
  const isInView = useInView(ref, {
    once: true,
    amount: (options.threshold ?? 0.1) as 'all' | 'some' | number,
  })
  const controls = useAnimation()

  useEffect(() => {
    if (isInView) {
      controls.start('visible')
    } else {
      controls.start('hidden')
    }
  }, [isInView, controls])

  return { ref, controls, isInView }
}

export function ScrollReveal({
  children,
  direction = 'up',
  distance = 24,
  delay = 0,
  duration = 0.6,
  className = '',
}: {
  children: React.ReactNode
  direction?: 'up' | 'down' | 'left' | 'right'
  distance?: number
  delay?: number
  duration?: number
  className?: string
}) {
  const { ref, controls } = useScrollReveal()

  const directionMap = {
    up: { y: distance, x: 0 },
    down: { y: -distance, x: 0 },
    left: { x: distance, y: 0 },
    right: { x: -distance, y: 0 },
  }

  const from = directionMap[direction]

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, ...from, filter: 'blur(8px)' }}
      animate={controls}
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
