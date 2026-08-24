import { useEffect, useRef, useState } from 'react'
import { useInView, animate } from 'framer-motion'

interface NumberTickerProps {
  value: number
  className?: string
  prefix?: string
  suffix?: string
  duration?: number
  decimals?: number
  separator?: boolean
}

export function NumberTicker({
  value,
  className = '',
  prefix = '',
  suffix = '',
  duration = 1.5,
  decimals = 0,
  separator = true,
}: NumberTickerProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: '-50px' })
  const [display, setDisplay] = useState('0')

  useEffect(() => {
    if (!inView) return

    const controls = animate(0, value, {
      duration,
      ease: [0.25, 0.46, 0.45, 0.94] as const,
      onUpdate(v) {
        let formatted: string
        if (decimals > 0) {
          formatted = v.toFixed(decimals)
        } else if (separator) {
          formatted = Math.round(v).toLocaleString()
        } else {
          formatted = Math.round(v).toString()
        }
        setDisplay(formatted)
      },
    })

    return () => controls.stop()
  }, [inView, value, duration, decimals, separator])

  return (
    <span ref={ref} className={className}>
      {prefix}
      {display}
      {suffix}
    </span>
  )
}
