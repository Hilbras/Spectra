import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Play, Loader2, CheckCircle2, Terminal, Info } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/hooks/useApi'

export function Audit() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [depth, setDepth] = useState<'quick' | 'full'>('full')
  const [format, setFormat] = useState('json')
  const [model, setModel] = useState('mock')
  const [running, setRunning] = useState(false)
  const [logs, setLogs] = useState<string[]>([])
  const [result, setResult] = useState<any>(null)
  const [progress, setProgress] = useState(0)
  const logsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    api.getConfig().then((cfg: any) => { if (cfg.defaultModel) setModel(cfg.defaultModel) })
  }, [])

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  async function startAudit() {
    if (!target.trim()) return
    setRunning(true)
    setResult(null)
    setLogs([])
    setProgress(5)

    try {
      const res = await api.triggerAudit(target, { depth, format, model })
      addLog(`Audit initiated: ${res.id}`)
      addLog(`Target: ${target} | Model: ${model} | Depth: ${depth}`)

      // Poll for completion
      const poll = setInterval(async () => {
        try {
          const data = await api.getAudit(res.id)
          const phase = data.investigation?.phase ?? 'running'
          setProgress(Math.min(95, 5 + Math.floor(data.iterations ?? 0) * 1.8))
          addLog(`Phase: ${phase.replace(/_/g, ' ')}`)
          const findings = data.investigation?.findings ?? []
          if (findings.length > (logs.filter(l => l.includes('findings')).length)) {
            addLog(`→ ${findings.length} finding${findings.length !== 1 ? 's' : ''} detected`)
          }
          if (data.investigation?.status === 'completed') {
            clearInterval(poll)
            setProgress(100)
            setResult(data)
            addLog('✓ Investigation complete')
            setTimeout(() => navigate('/findings'), 1200)
          }
        } catch {
          clearInterval(poll)
          addLog('Error checking status')
        }
      }, 2500)
      setTimeout(() => clearInterval(poll), 90000)
    } catch (err) {
      addLog(`ERROR: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setRunning(false)
    }
  }

  function addLog(msg: string) {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [...prev, `[${time}] ${msg}`])
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate('/')} className="rounded-xl">
          <ArrowLeft className="size-4" />
        </Button>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">New Audit</h1>
          <p className="text-sm text-muted-foreground">Configure and run a security investigation</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Config */}
        <Card className="glass">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Terminal className="size-4 text-gold-500" /> Configuration
            </CardTitle>
            <CardDescription>Target project and investigation parameters</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Target Path or Profile Name</label>
              <Input
                placeholder="./my-project or profile-name"
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={running}
                className="rounded-xl"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Depth</label>
                <select value={depth} onChange={e => setDepth(e.target.value as any)} disabled={running}
                  className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-gold-500/40">
                  <option value="quick">Quick (20 iters)</option>
                  <option value="full">Full (50 iters)</option>
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Format</label>
                <select value={format} onChange={e => setFormat(e.target.value)} disabled={running}
                  className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-gold-500/40">
                  <option value="json">JSON</option>
                  <option value="sarif">SARIF 2.1</option>
                  <option value="markdown">Markdown</option>
                </select>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">AI Model</label>
              <select value={model} onChange={e => setModel(e.target.value)} disabled={running}
                className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-gold-500/40">
                <option value="mock">Mock (deterministic testing)</option>
                <option value="openai">OpenAI GPT-4o</option>
                <option value="anthropic">Anthropic Claude</option>
                <option value="groq">Groq Llama</option>
                <option value="ollama">Ollama (local)</option>
              </select>
            </div>

            <Button
              onClick={startAudit}
              disabled={running || !target.trim()}
              variant="gold"
              className="w-full gap-2 rounded-xl h-11"
            >
              {running ? <><Loader2 className="size-4 animate-spin" /> Investigating...</> : <><Play className="size-4" /> Start Investigation</>}
            </Button>

            <div className="flex items-start gap-2 p-3 rounded-xl bg-gold-500/5 border border-gold-500/10">
              <Info className="size-4 text-gold-500 shrink-0 mt-0.5" />
              <p className="text-xs text-muted-foreground leading-relaxed">
                <strong className="text-foreground">Quick mode</strong> runs 20 iterations for fast results.<br />
                <strong className="text-foreground">Full mode</strong> runs 50 iterations for thorough analysis.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Live output */}
        <Card className="glass">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Terminal className="size-4 text-gold-500" /> Live Output
              {running && <span className="ml-auto flex items-center gap-1.5 text-xs text-green-500"><span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> Running</span>}
              {result && <span className="ml-auto flex items-center gap-1.5 text-xs text-green-500"><CheckCircle2 className="size-3" /> Complete</span>}
            </CardTitle>
            <CardDescription>Real-time investigation progress</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="bg-muted/50 rounded-xl p-4 font-mono text-xs space-y-1 min-h-48 max-h-80 overflow-y-auto">
              {logs.length === 0 ? (
                <p className="text-muted-foreground italic">Ready to start investigation...</p>
              ) : logs.map((log, i) => (
                <div key={i} className={`${
                  log.includes('ERROR') ? 'text-red-400' :
                  log.includes('✓') ? 'text-green-400' :
                  log.includes('Phase') ? 'text-gold-400' :
                  'text-muted-foreground'
                }`}>
                  {log}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>

            {running && (
              <div className="mt-4 space-y-2">
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Progress</span>
                  <span>{progress}%</span>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-gold-400 to-gold-600 rounded-full transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
            )}

            {result && (
              <div className="mt-4 p-4 rounded-xl bg-green-500/10 border border-green-500/20">
                <div className="flex items-center gap-2 text-green-500 font-medium text-sm">
                  <CheckCircle2 className="size-4" /> Investigation Complete
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {(result.summary?.criticalCount ?? 0) + (result.summary?.highCount ?? 0)} critical/high findings · Score: {result.summary?.overallScore ?? '?'}/100
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
