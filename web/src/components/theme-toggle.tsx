import { motion, AnimatePresence } from 'framer-motion'
import { Moon, Sun } from 'lucide-react'
import { useTheme } from './theme-provider'
import { Button } from './ui/button'

export function ThemeToggle() {
  const { theme, setTheme } = useTheme()

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
      className="rounded-xl hover:bg-gold-500/10 relative w-9 h-9 overflow-hidden"
    >
      <div className="relative w-5 h-5">
        <AnimatePresence mode="wait">
          {theme === 'dark' ? (
            <motion.div
              key="sun"
              initial={{ rotate: -90, opacity: 0, scale: 0.5 }}
              animate={{ rotate: 0, opacity: 1, scale: 1 }}
              exit={{ rotate: 90, opacity: 0, scale: 0.5 }}
              transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <Sun className="size-4 text-gold-400" />
            </motion.div>
          ) : (
            <motion.div
              key="moon"
              initial={{ rotate: 90, opacity: 0, scale: 0.5 }}
              animate={{ rotate: 0, opacity: 1, scale: 1 }}
              exit={{ rotate: -90, opacity: 0, scale: 0.5 }}
              transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <Moon className="size-4 text-gold-600" />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Button>
  )
}
