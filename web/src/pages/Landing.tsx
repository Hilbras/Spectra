import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Upload, Link as LinkIcon, FolderGit2, Bug, Activity, CheckCircle2, Zap, ArrowRight, Globe2, Code2, FileSearch, AlertTriangle, Lock } from 'lucide-react'
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

  useState(() => {
    api.getHealth().then(setHealth).catch(() => {})
  })

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
    <div className="relative flex flex-col min-h-full bg-background">
      {/* Background effects */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-gold-500/5 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-gold-600/5 rounded-full blur-[100px]" />
        <div
          className="absolute inset-0 opacity-[0.02] dark:opacity-[0.04]"
          style={{ backgroundImage: 'radial-gradient(circle, currentColor 1px, transparent 1px)', backgroundSize: '32px 32px' }}
        />
      </div>

      {/* Navbar */}
      <header className="fixed top-0 inset-x-0 z-50 px-4 py-4 sm:px-6">
        <div className="mx-auto max-w-7xl">
          <div className="glass rounded-2xl flex items-center justify-between h-14 px-5 border border-border/40">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-gold-400 to-gold-600 shadow-md shadow-gold-500/20">
                <Shield className="size-4 text-black" />
              </div>
              <span className="font-bold text-sm tracking-tight">Hilbras Spectra</span>
            </div>
            <nav className="hidden md:flex items-center gap-8 text-sm text-muted-foreground">
              <a href="#features" className="hover:text-foreground transition-colors">Features</a>
              <a href="#how-it-works" className="hover:text-foreground transition-colors">How it Works</a>
              <a href="#stats" className="hover:text-foreground transition-colors">Stats</a>
            </nav>
            <div className="flex items-center gap-1">
              <ThemeToggle />
              <Button variant="ghost" size="sm" className="rounded-xl text-xs h-8 px-3" onClick={() => navigate('/settings')}>
                Settings
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative z-10 pt-32 pb-20 px-4">
        <div className="mx-auto max-w-7xl">
          <div className="text-center max-w-4xl mx-auto">
            {/* Badge */}
            <div className="mb-6 fade-in">
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-gold-500/10 text-gold-600 dark:text-gold-400 border border-gold-500/20">
                <Bug className="size-3" />
                AI-Powered Security Research Platform
              </span>
            </div>

            {/* Title */}
            <h1 className="text-5xl sm:text-6xl md:text-7xl font-extrabold tracking-tight fade-in" style={{ animationDelay: '0.1s' }}>
              Analyze any codebase
              <br />
              <span className="bg-gradient-to-r from-gold-400 via-gold-500 to-gold-700 bg-clip-text text-transparent">
                in seconds
              </span>
            </h1>

            {/* Subtitle */}
            <p className="mt-6 text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed fade-in" style={{ animationDelay: '0.2s' }}>
              Hilbras Spectra uses autonomous AI agents to investigate dependencies, attack surfaces, and security vulnerabilities — then delivers actionable reports you can act on immediately.
            </p>

            {/* Mode Toggle */}
            <div className="mt-10 flex items-center justify-center gap-1 p-1 rounded-2xl glass border border-border/40 fade-in" style={{ animationDelay: '0.3s' }}>
              <button
                onClick={() => setMode('link')}
                className={`flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
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
                className={`flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${
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
            <div className="mt-6 w-full max-w-4xl fade-in" style={{ animationDelay: '0.4s' }}>
              <div className="glass rounded-2xl p-6 space-y-4 border border-border/40">
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
                  className="w-full rounded-xl gap-2 h-12 text-base"
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
                      <ArrowRight className="size-4" />
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section id="stats" className="relative z-10 py-16 px-4 border-y border-border/30">
        <div className="mx-auto max-w-7xl">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {[
              { value: '20+', label: 'Analysis Phases', icon: Activity },
              { value: '50+', label: 'Vulnerability Types', icon: Bug },
              { value: '4', label: 'Language Support', icon: Code2 },
              { value: '<30s', label: 'Average Scan Time', icon: Zap },
            ].map(({ value, label, icon: Icon }) => (
              <div key={label} className="text-center">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-gold-500/10 mb-3">
                  <Icon className="size-6 text-gold-500" />
                </div>
                <p className="text-3xl font-extrabold text-gold-500">{value}</p>
                <p className="text-sm text-muted-foreground mt-1">{label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="relative z-10 py-24 px-4">
        <div className="mx-auto max-w-7xl">
          <div className="text-center mb-16">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-600 dark:text-gold-400 border border-gold-500/20 mb-4">
              Features
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
              Everything you need for{' '}
              <span className="bg-gradient-to-r from-gold-400 to-gold-600 bg-clip-text text-transparent">
                security research
              </span>
            </h2>
            <p className="mt-4 text-muted-foreground max-w-xl mx-auto">
              From dependency analysis to attack surface mapping — get comprehensive security insights in minutes.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              {
                icon: Bug,
                title: 'Dependency Analysis',
                desc: 'Automatically scan your dependencies for known vulnerabilities, outdated packages, and license issues.',
              },
              {
                icon: Globe2,
                title: 'Attack Surface Mapping',
                desc: 'Visualize every entry point, API endpoint, and potential vector an attacker could exploit.',
              },
              {
                icon: Code2,
                title: 'Taint Analysis',
                desc: 'Trace data flow through your codebase to find injection points and data leakage vulnerabilities.',
              },
              {
                icon: FileSearch,
                title: 'Configuration Review',
                desc: 'Detect misconfigurations, hardcoded secrets, and insecure defaults in your deployment setup.',
              },
              {
                icon: Lock,
                title: 'Policy Enforcement',
                desc: 'Define custom security policies and get automated compliance reporting against them.',
              },
              {
                icon: AlertTriangle,
                title: 'CVE Feed Integration',
                desc: 'Stay updated with real-time CVE feeds to identify newly discovered vulnerabilities in your stack.',
              },
            ].map(({ icon: Icon, title, desc }) => (
              <div key={title} className="group glass rounded-2xl p-6 border border-border/40 hover:border-gold-500/30 transition-all duration-300 hover:shadow-lg hover:shadow-gold-500/5">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-gold-400 to-gold-600 flex items-center justify-center mb-4 shadow-md shadow-gold-500/20">
                  <Icon className="size-6 text-black" />
                </div>
                <h3 className="text-lg font-semibold mb-2">{title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it Works */}
      <section id="how-it-works" className="relative z-10 py-24 px-4 border-t border-border/30">
        <div className="mx-auto max-w-7xl">
          <div className="text-center mb-16">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-600 dark:text-gold-400 border border-gold-500/20 mb-4">
              How it Works
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
              Three steps to{' '}
              <span className="bg-gradient-to-r from-gold-400 to-gold-600 bg-clip-text text-transparent">
                security clarity
              </span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                step: '01',
                title: 'Connect Your Project',
                desc: 'Link your repository or upload your project archive. We support Git URLs, GitHub repos, and common archive formats.',
              },
              {
                step: '02',
                title: 'AI Investigation',
                desc: 'Our autonomous AI agent runs through 20+ analysis phases, examining dependencies, code patterns, and configurations.',
              },
              {
                step: '03',
                title: 'Get Actionable Reports',
                desc: 'Receive detailed findings with severity ratings, remediation guidance, and exportable reports in SARIF or JSON format.',
              },
            ].map(({ step, title, desc }, i) => (
              <div key={step} className="relative">
                <div className="glass rounded-2xl p-8 border border-border/40 h-full">
                  <span className="text-5xl font-extrabold bg-gradient-to-br from-gold-400 to-gold-600 bg-clip-text text-transparent">
                    {step}
                  </span>
                  <h3 className="mt-4 text-xl font-semibold">{title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground leading-relaxed">{desc}</p>
                </div>
                {i < 2 && (
                  <div className="hidden md:block absolute top-1/2 -right-4 text-gold-500">
                    <ArrowRight className="size-6" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Supported Languages */}
      <section className="relative z-10 py-24 px-4 border-t border-border/30">
        <div className="mx-auto max-w-7xl">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-600 dark:text-gold-400 border border-gold-500/20 mb-4">
              Supported Languages
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
              Multi-language{' '}
              <span className="bg-gradient-to-r from-gold-400 to-gold-600 bg-clip-text text-transparent">
                analysis
              </span>
            </h2>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {['TypeScript', 'JavaScript', 'Python', 'Go'].map((lang) => (
              <div key={lang} className="glass rounded-xl p-6 text-center border border-border/40 hover:border-gold-500/30 transition-colors">
                <Code2 className="size-8 text-gold-500 mx-auto mb-3" />
                <p className="font-medium">{lang}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative z-10 py-24 px-4">
        <div className="mx-auto max-w-4xl">
          <div className="relative rounded-3xl border border-gold-500/20 bg-gradient-to-b from-gold-500/[0.07] to-transparent p-12 text-center overflow-hidden">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] bg-gold-500/10 rounded-full blur-[100px] pointer-events-none" />
            <div className="relative">
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
                Ready to secure your project?
              </h2>
              <p className="mt-4 text-muted-foreground max-w-md mx-auto">
                Start your first security investigation today. No configuration required.
              </p>
              <div className="mt-8 flex items-center justify-center gap-4">
                <Button variant="gold" size="lg" className="rounded-xl gap-2" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
                  Get Started Free <ArrowRight className="size-4" />
                </Button>
              </div>
              <p className="mt-4 text-xs text-muted-foreground flex items-center justify-center gap-1.5">
                <CheckCircle2 className="size-3.5 text-gold-500" />
                No credit card required · Free tier available · Stop anytime
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-border py-12 px-4">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-gold-400 to-gold-600">
                <Shield className="size-4 text-black" />
              </div>
              <span className="font-bold text-sm">Hilbras Spectra</span>
            </div>
            <nav className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-muted-foreground">
              <a href="#features" className="hover:text-foreground transition-colors">Features</a>
              <a href="#how-it-works" className="hover:text-foreground transition-colors">How it Works</a>
              <a href="#stats" className="hover:text-foreground transition-colors">Stats</a>
            </nav>
            <p className="text-xs text-muted-foreground">
              © {new Date().getFullYear()} Hilbras Spectra. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}
