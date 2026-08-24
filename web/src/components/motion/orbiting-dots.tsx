import { motion } from 'framer-motion'

interface OrbitingDotsProps {
  count?: number
  radius?: number
  duration?: number
  dotSize?: number
  className?: string
}

export function OrbitingDots({
  count = 8,
  radius = 40,
  duration = 12,
  dotSize = 4,
  className = '',
}: OrbitingDotsProps) {
  return (
    <div
      className={`relative ${className}`}
      style={{ width: radius * 2 + dotSize * 2, height: radius * 2 + dotSize * 2 }}
    >
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration, repeat: Infinity, ease: 'linear' as const }}
        className="absolute inset-0"
      >
        {Array.from({ length: count }).map((_, i) => {
          const angle = (360 / count) * i
          const rad = (angle * Math.PI) / 180
          const x = radius + radius * Math.cos(rad)
          const y = radius + radius * Math.sin(rad)
          const opacity = 0.3 + (i / count) * 0.7
          return (
            <motion.div
              key={i}
              className="absolute rounded-full bg-gold-500"
              style={{
                width: dotSize,
                height: dotSize,
                left: x,
                top: y,
                opacity,
              }}
              animate={{
                scale: [1, 1.5, 1],
                opacity: [opacity, 1, opacity],
              }}
              transition={{
                duration: 2,
                repeat: Infinity,
                delay: (i / count) * 2,
              }}
            />
          )
        })}
      </motion.div>
    </div>
  )
}
