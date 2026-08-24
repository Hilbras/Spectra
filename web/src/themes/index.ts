export type ThemeName = 'dark' | 'light'

export interface ThemeTokens {
  bg: string
  bgSecondary: string
  bgTertiary: string
  bgPanel: string
  bgHover: string
  text: string
  textSecondary: string
  textMuted: string
  border: string
  borderBright: string
  accent: string
  accentDim: string
  gold: string
  goldDim: string
  success: string
  error: string
  warning: string
  info: string
  critical: string
  high: string
  medium: string
  low: string
  shadow: string
  gradient: string
}

export const dark: ThemeTokens = {
  bg: '#0d1117',
  bgSecondary: '#161b22',
  bgTertiary: '#21262d',
  bgPanel: '#1c2128',
  bgHover: '#292e36',
  text: '#e6edf3',
  textSecondary: '#8b949e',
  textMuted: '#6e7681',
  border: '#30363d',
  borderBright: '#f0c040',
  accent: '#58a6ff',
  accentDim: '#1f6feb20',
  gold: '#ffd700',
  goldDim: '#ffd70030',
  success: '#3fb950',
  error: '#f85149',
  warning: '#d29922',
  info: '#58a6ff',
  critical: '#ff3333',
  high: '#f85149',
  medium: '#d29922',
  low: '#58a6ff',
  shadow: '0 3px 12px rgba(0,0,0,0.5)',
  gradient: 'linear-gradient(135deg, #0d1117 0%, #161b22 100%)',
}

export const light: ThemeTokens = {
  bg: '#f6f8fa',
  bgSecondary: '#ffffff',
  bgTertiary: '#eaeef2',
  bgPanel: '#ffffff',
  bgHover: '#f3f4f6',
  text: '#1f2328',
  textSecondary: '#656d76',
  textMuted: '#9198a1',
  border: '#d0d7de',
  borderBright: '#b8860b',
  accent: '#0969da',
  accentDim: '#0969da15',
  gold: '#b8860b',
  goldDim: '#b8860b20',
  success: '#1a7f37',
  error: '#cf222e',
  warning: '#9a6700',
  info: '#0969da',
  critical: '#cf222e',
  high: '#cf222e',
  medium: '#9a6700',
  low: '#0969da',
  shadow: '0 3px 12px rgba(0,0,0,0.1)',
  gradient: 'linear-gradient(135deg, #f6f8fa 0%, #eaeef2 100%)',
}

export function getTheme(name: ThemeName): ThemeTokens {
  return name === 'dark' ? dark : light
}
