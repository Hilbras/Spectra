import { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface TypingTextProps {
  texts: string[]
  typingSpeed?: number
  deletingSpeed?: number
  pauseDuration?: number
  className?: string
}

export function TypingText({
  texts,
  typingSpeed = 50,
  deletingSpeed = 30,
  pauseDuration = 2000,
  className = '',
}: TypingTextProps) {
  const [textIndex, setTextIndex] = useState(0)
  const [subTextIndex, setSubTextIndex] = useState(0)
  const [isDeleting, setIsDeleting] = useState(false)

  const currentText = texts[textIndex]

  const timeout = useCallback(() => {
    if (!isDeleting && subTextIndex === currentText.length) {
      setTimeout(() => setIsDeleting(true), pauseDuration)
      return
    }

    if (isDeleting && subTextIndex === 0) {
      setIsDeleting(false)
      setTextIndex((prev) => (prev + 1) % texts.length)
      return
    }

    setSubTextIndex((prev) => prev + (isDeleting ? -1 : 1))
  }, [isDeleting, subTextIndex, currentText, texts, pauseDuration])

  useEffect(() => {
    const t = setTimeout(timeout, isDeleting ? deletingSpeed : typingSpeed)
    return () => clearTimeout(t)
  }, [timeout, isDeleting, typingSpeed, deletingSpeed])

  return (
    <span className={className}>
      {currentText.slice(0, subTextIndex)}
      <motion.span
        animate={{ opacity: [1, 0] }}
        transition={{ duration: 0.6, repeat: Infinity, repeatType: 'reverse' }}
        className="inline-block w-0.5 h-4 bg-gold-500 ml-0.5 align-middle"
      />
    </span>
  )
}
