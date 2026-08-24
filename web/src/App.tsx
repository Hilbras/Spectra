import { useState } from 'react'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence, motion, easeInOut } from 'framer-motion'
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
import { Landing } from './pages/Landing'

const APP_ROUTES = ['/audit', '/findings', '/history', '/projects', '/settings', '/health', '/benchmarks']

// Page transition config for app routes
const pageTransition = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
  transition: { duration: 0.2, ease: easeInOut },
}

function Layout({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()
  const isApp = APP_ROUTES.some(r => location.pathname.startsWith(r))

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      {isApp && (
        <>
          <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
          <div className="flex flex-col flex-1 min-w-0">
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
            <main className="flex-1 overflow-y-auto">
              <AnimatePresence mode="wait">
                <motion.div key={location.pathname} {...pageTransition}>
                  <div className="p-6 lg:p-8 max-w-7xl mx-auto">
                    {children}
                  </div>
                </motion.div>
              </AnimatePresence>
            </main>
          </div>
        </>
      )}
      {!isApp && (
        <div className="w-full h-full overflow-y-auto">
          <AnimatePresence mode="wait">
            <motion.div key={location.pathname} {...pageTransition}>
              {children}
            </motion.div>
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/history" element={<History />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/health" element={<Health />} />
            <Route path="/benchmarks" element={<Benchmarks />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </ThemeProvider>
  )
}
