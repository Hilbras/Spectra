import { NavLink, useNavigate } from 'react-router-dom'
import { useTheme } from '../hooks/useTheme'
import type { ThemeTokens } from '../themes'

interface LayoutProps { children: React.ReactNode }

const navItems = [
  { to: '/', label: 'Dashboard', icon: '◈' },
  { to: '/audit', label: 'New Audit', icon: '▶' },
  { to: '/findings', label: 'Findings', icon: '⚠' },
  { to: '/history', label: 'History', icon: '◷' },
  { to: '/projects', label: 'Projects', icon: '◇' },
  { to: '/settings', label: 'Settings', icon: '⚙' },
]

export function Layout({ children }: LayoutProps) {
  const { themeName, toggleTheme } = useTheme()
  const navigate = useNavigate()
  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <span>🔍</span>
            <div>
              <div>Spectra</div>
              <div className="sidebar-version">v0.0.6 · Security Research</div>
            </div>
          </div>
        </div>
        
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <button className="btn btn-sm" onClick={() => navigate('/health')} title="Health Check">
            🩺 Health
          </button>
          <button className="btn btn-sm" onClick={toggleTheme} title={`Switch to ${themeName === 'dark' ? 'light' : 'dark'} theme`}>
            {themeName === 'dark' ? '☀️' : '🌙'}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="main-content">
        {children}
      </main>
    </div>
  )
}
