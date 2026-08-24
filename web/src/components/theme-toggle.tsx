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
      className="rounded-xl hover:bg-gold-500/10"
    >
      {theme === 'dark' ? (
        <Sun className="size-4 text-gold-400" />
      ) : (
        <Moon className="size-4 text-gold-600" />
      )}
    </Button>
  )
}
