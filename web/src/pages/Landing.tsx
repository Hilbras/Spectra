import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Upload, Link as LinkIcon, FolderGit2, Bug, Activity } from 'lucide-react'
import { api } from '@/hooks/useApi'
import { Button } from '@/components/ui/button'
import { ThemeToggle } from '@/components/theme-toggle'

export function Landing() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<'link' | 'upload'>('link')
  const [input, setInput] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [health, setHealth] = useState<any>(null)

  // Load health on mount
  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => {})
  }, [])

  async function startAudit() {
    setError('')
    if (!input.trim()) { setError('Please enter a project path or URL'); return }
    setLoading(true)
    try {
      const res = await api.triggerAudit(input.trim(), { mode })
      navigate('/audit', { state: { auditId: res.id } })
    } catch (e: any) {
      setError(e.message ?? 'Failed to start audit')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col min-h-screen">
      {/* Navbar */}
      <header className="fixed top-0 inset-x-0 z-50 px-6 py-4">
        <div className="mx-auto max-w-5xl">
          <div className="glass rounded-2xl flex items-center justify-between h-14 px-5">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-gold-400 to-gold-600 shadow-md shadow-gold-500/20">
                <Shield className="size-4 text-black" />
              </div>
              <span className="font-bold text-sm tracking-tight">Hilbras Spectra</span>
            </div>
            <nav className="hidden md:flex items-center gap-6 text-sm text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Activity className="size-3.5 text-green-500" />
                {health?.status === 'ok' ? 'System Ready' : 'Initializing...'}
              </span>
            </nav>
            <ThemeToggle />
            <Button variant="ghost" size="sm" className="rounded-xl text-xs" onClick={() => navigate('/settings')}>
              Settings
            </Button>
          </div>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 pt-24 pb-16">
        {/* Badge */}
        <div className="mb-6 fade-in">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-600 dark:text-gold-400 border border-gold-500/20">
            <Bug className="size-3" />
            AI-Powered Security Research
          </span>
        </div>

        {/* Title */}
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-center fade-in" style={{ animationDelay: '0.1s' }}>
          Analyze any project
          <br />
          <span className="bg-gradient-to-r from-gold-400 via-gold-500 to-gold-700 bg-clip-text text-transparent">
            in seconds
          </span>
        </h1>

        <p className="mt-4 text-base text-muted-foreground text-center max-w-lg leading-relaxed fade-in" style={{ animationDelay: '0.2s' }}>
          Hilbras Spectra uses AI to investigate dependencies, attack surfaces, and security flaws. Connect your project and get actionable results.
        </p>

        {/* Mode Toggle */}
        <div className="mt-10 flex items-center gap-1 p-1 rounded-2xl glass fade-in" style={{ animationDelay: '0.3s' }}>
          <button
            onClick={() => setMode('link')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 ${
              mode === 'link'
                ? 'bg-gold-500 text-black shadow-md shadow-gold-500/25'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <LinkIcon className="size-4" />
            Link Project
          </button>
          <button
            onClick={() => setMode('upload')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 ${
              mode === 'upload'
                ? 'bg-gold-500 text-black shadow-md shadow-gold-500/25'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <Upload className="size-4" />
            Upload Project
          </button>
        </div>

        {/* Input Area */}
        <div className="mt-6 w-full max-w-xl fade-in" style={{ animationDelay: '0.4s' }}>
          <div className="glass rounded-2xl p-6 space-y-4">
            {mode === 'link' ? (
              <>
                <div className="flex items-center gap-3">
                  <FolderGit2 className="size-5 text-gold-500 shrink-0" />
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Enter project path (e.g. ./my-app) or repository URL"
                    className="flex-1 bg-transparent border-none outline-none text-sm placeholder:text-muted-foreground"
                    onKeyDown={(e) => e.key === 'Enter' && startAudit()}
                  />
                </div>
                <p className="text-xs text-muted-foreground pl-8">
                  Supports local paths, Git URLs, and GitHub repositories
                </p>
              </>
            ) : (
              <>
                <label
                  htmlFor="file-upload"
                  className="flex flex-col items-center justify-center h-32 border-2 border-dashed rounded-xl cursor-pointer transition-colors hover:border-gold-500/50 group"
                  style={{ borderColor: file ? 'var(--gold-500)' : undefined }}
                >
                  {file ? (
                    <div className="flex flex-col items-center gap-2">
                      <FolderGit2 className="size-6 text-gold-500" />
                      <span className="text-sm font-medium">{file.name}</span>
                      <span className="text-xs text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</span>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2">
                      <Upload className="size-6 text-muted-foreground group-hover:text-gold-500 transition-colors" />
                      <span className="text-sm text-muted-foreground">Drop your project archive here</span>
                      <span className="text-xs text-muted-foreground">.zip, .tar.gz, or .tgz</span>
                    </div>
                  )}
                </label>
                <input
                  id="file-upload"
                  type="file"
                  accept=".zip,.tar.gz,.tgz"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    if (f) setFile(f)
                  }}
                />
              </>
            )}

            {error && (
              <p className="text-xs text-red-500 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-red-500 shrink-0" />
                {error}
              </p>
            )}

            <Button
              variant="gold"
              size="lg"
              className="w-full rounded-xl gap-2"
              disabled={loading || !input.trim() || (mode === 'upload' && !file)}
              onClick={startAudit}
            >
              {loading ? (
                <>
                  <Activity className="size-4 animate-spin" style={{ animationDuration: '1.5s' }} />
                  Starting investigation...
                </>
              ) : (
                <>
                  <Shield className="size-4" />
                  {mode === 'link' ? 'Link & Investigate' : 'Upload & Investigate'}
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Feature pills */}
        <div className="mt-12 flex flex-wrap items-center justify-center gap-3 fade-in" style={{ animationDelay: '0.5s' }}>
          {[
            { icon: Bug, label: '20+ Phases' },
            { icon: Shield, label: 'Policy-Gated Tools' },
            { icon: Activity, label: 'AI-Powered' },
            { icon: FolderGit2, label: 'Multi-Language' },
          ].map(({ icon: Icon, label }) => (
            <div key={label} className="flex items-center gap-2 px-4 py-2 rounded-xl glass text-xs text-muted-foreground">
              <Icon className="size-3.5 text-gold-500" />
              {label}
            </div>
          ))}
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 text-center text-xs text-muted-foreground">
        <p>Hilbras Spectra v0.0.6 — AI Security Research Platform</p>
      </footer>
    </div>
  )
}
