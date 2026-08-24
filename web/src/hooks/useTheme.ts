import { useState, useCallback } from 'react'
import { ThemeName, getTheme, ThemeTokens } from '../themes'

export function useTheme() {
  const [themeName, setThemeState] = useState<ThemeName>(() => {
    const stored = localStorage.getItem('spectra-theme')
    return (stored === 'light' || stored === 'dark') ? stored : 'dark'
  })
  const [tokens, setTokens] = useState<ThemeTokens>(() => getTheme(themeName))

  const setTheme = useCallback((name: ThemeName) => {
    setThemeState(name)
    setTokens(getTheme(name))
    localStorage.setItem('spectra-theme', name)
    document.documentElement.setAttribute('data-theme', name)
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(themeName === 'dark' ? 'light' : 'dark')
  }, [themeName, setTheme])

  return { themeName, tokens, setTheme, toggleTheme }
}
