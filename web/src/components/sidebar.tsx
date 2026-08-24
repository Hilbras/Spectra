import { useMemo } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Search, History, Bug, Server, Users,
  Settings, ChevronLeft, ChevronRight, Shield, Zap, BarChart3,
} from 'lucide-react'
import { cn } from './lib/utils'
import { ThemeToggle } from './theme-toggle'

const NAV = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/audit', label: 'New Audit', icon: Zap },
  { href: '/findings', label: 'Findings', icon: Bug },
  { href: '/history', label: 'History', icon: History },
  { href: '/benchmarks', label: 'Benchmarks', icon: BarChart3 },
  { href: '/projects', label: 'Projects', icon: Users },
  { href: '/health', label: 'Health', icon: Server },
  { href: '/settings', label: 'Settings', icon: Settings },
] as const

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const location = useLocation()

  return (
    <aside
      className={cn(
        'relative flex flex-col h-full border-r border-border/50 transition-all duration-300 ease-in-out',
        'bg-card/80 backdrop-blur-xl',
        collapsed ? 'w-[68px]' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 h-16 px-4 border-b border-border/50">
        <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-gold-400 to-gold-600 shadow-md shadow-gold-500/25 shrink-0">
          <Shield className="size-4 text-black" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <span className="font-bold text-sm tracking-tight block leading-tight">
              Hilbras Spectra
            </span>
            <span className="text-[10px] text-muted-foreground leading-tight">
              Security Research · v0.0.6
            </span>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-1">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = location.pathname === href || location.pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              to={href}
              className={cn(
                'group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200',
                active
                  ? 'bg-gold-500/15 text-gold-600 dark:text-gold-400 shadow-sm shadow-gold-500/5'
                  : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground hover:shadow-sm'
              )}
            >
              <Icon className={cn(
                'size-[18px] shrink-0 transition-transform duration-200 group-hover:scale-110',
                active && 'text-gold-500 dark:text-gold-400'
              )} />
              {!collapsed && <span>{label}</span>}
              {active && !collapsed && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-gold-500" />
              )}
            </Link>
          )
        })}
      </nav>

      {/* Footer actions */}
      <div className="px-3 py-3 border-t border-border/50 flex items-center justify-between">
        {!collapsed && <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-widest px-2">Actions</span>}
        <ThemeToggle />
        <button
          onClick={onToggle}
          className="flex items-center justify-center w-7 h-7 rounded-full border border-border bg-muted text-muted-foreground hover:text-gold-500 hover:border-gold-500/40 transition-all duration-200"
        >
          {collapsed ? <ChevronRight className="size-3" /> : <ChevronLeft className="size-3" />}
        </button>
      </div>
    </aside>
  )
}
