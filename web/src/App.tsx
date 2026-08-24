import { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/sidebar'
import { ThemeProvider } from './components/theme-provider'
import { ThemeToggle } from './components/theme-toggle'
import { Search, Bell } from 'lucide-react'
import { Dashboard } from './pages/Dashboard'
import { Audit } from './pages/Audit'
import { Findings } from './pages/Findings'
import { AuditHistory as History } from './pages/History'
import { Projects } from './pages/Projects'
import { Settings } from './pages/Settings'
import { Health } from './pages/Health'
import { Benchmarks } from './pages/Benchmarks'

export default function App() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <ThemeProvider>
      <BrowserRouter>
        <div className="flex h-screen overflow-hidden bg-background text-foreground">
          <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />

          <div className="flex flex-col flex-1 min-w-0">
            {/* Header */}
            <header className="glass sticky top-0 z-30 flex items-center h-16 px-6 border-b border-border/50">
              <div className="flex items-center gap-3 flex-1 max-w-md">
                <Search className="size-4 text-muted-foreground shrink-0" />
                <input
                  placeholder="Search findings, audits, projects..."
                  className="flex-1 bg-transparent border-none outline-none text-sm placeholder:text-muted-foreground"
                />
              </div>

              <div className="flex items-center gap-1 ml-auto">
                <button className="relative p-2 rounded-xl hover:bg-gold-500/10 transition-colors">
                  <Bell className="size-4 text-muted-foreground" />
                  <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-gold-500 animate-[pulse-gold_2s_ease-in-out_infinite]" />
                </button>
                <ThemeToggle />
              </div>
            </header>

            {/* Page content */}
            <main className="flex-1 overflow-y-auto">
              <div className="p-6 lg:p-8 max-w-7xl mx-auto">
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/audit" element={<Audit />} />
                  <Route path="/findings" element={<Findings />} />
                  <Route path="/history" element={<History />} />
                  <Route path="/projects" element={<Projects />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/health" element={<Health />} />
                  <Route path="/benchmarks" element={<Benchmarks />} />
                </Routes>
              </div>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </ThemeProvider>
  )
}
