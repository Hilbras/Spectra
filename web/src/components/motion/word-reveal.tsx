import { motion } from 'framer-motion'

interface WordRevealProps {
  text: string
  className?: string
  delay?: number
  staggerDelay?: number
}

export function WordReveal({
  text,
  className = '',
  delay = 0,
  staggerDelay = 0.04,
}: WordRevealProps) {
  const words = text.split(' ')

  return (
    <motion.span
      className={className}
      initial="hidden"
      animate="visible"
      variants={{
        hidden: {},
        visible: {
          transition: {
            staggerChildren: staggerDelay,
            delayChildren: delay,
          },
        },
      }}
    >
      {words.map((word, i) => (
        <span key={i} className="inline-block mr-[0.3em]">
          <motion.span
            className="inline-block"
            variants={{
              hidden: { opacity: 0, y: 20, filter: 'blur(6px)' },
              visible: {
                opacity: 1,
                y: 0,
                filter: 'blur(0px)',
                transition: {
                  duration: 0.4,
                  ease: [0.25, 0.46, 0.45, 0.94] as const,
                },
              },
            }}
          >
            {word}
          </motion.span>
        </span>
      ))}
    </motion.span>
  )
}
