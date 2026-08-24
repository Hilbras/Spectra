import { motion } from 'framer-motion'

const ORBS = [
  { color: 'var(--color-gold-500)', size: 600, x: '20%', y: '10%', delay: 0 },
  { color: 'var(--color-gold-700)', size: 400, x: '70%', y: '60%', delay: 2 },
  { color: 'var(--color-gold-300)', size: 500, x: '50%', y: '30%', delay: 4 },
]

export function GradientMesh({ className = '' }: { className?: string }) {
  return (
    <div className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`}>
      {ORBS.map((orb, i) => (
        <motion.div
          key={i}
          className="absolute rounded-full opacity-[0.04] dark:opacity-[0.06] blur-3xl"
          style={{
            width: orb.size,
            height: orb.size,
            left: orb.x,
            top: orb.y,
            background: `radial-gradient(circle, ${orb.color}, transparent 70%)`,
          }}
          animate={{
            x: [0, 40, -30, 20, 0],
            y: [0, -30, 20, -40, 0],
            scale: [1, 1.1, 0.95, 1.05, 1],
          }}
          transition={{
            duration: 20 + i * 5,
            repeat: Infinity,
            ease: 'easeInOut' as const,
            delay: orb.delay,
          }}
        />
      ))}
    </div>
  )
}
