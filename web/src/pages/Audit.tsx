import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../hooks/useApi'

export function Audit() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [depth, setDepth] = useState<'quick' | 'full'>('full')
  const [format, setFormat] = useState('json')
  const [model, setModel] = useState('mock')
  const [dryRun, setDryRun] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<string>('')
  const [logs, setLogs] = useState<string[]>([])
  const [result, setResult] = useState<any>(null)
  const logsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => { api.getConfig().then((cfg: any) => { if (cfg.defaultModel) setModel(cfg.defaultModel) }) }, [])
  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])

  async function startAudit() {
    if (!target.trim()) return
    setRunning(true)
    setResult(null)
    setLogs([])
    setProgress('Initializing...')

    try {
      const res = await api.triggerAudit(target, { depth, format, model, dryRun })
      setProgress(`Audit started: ${res.id}`)
      setLogs([...logs, `[${new Date().toISOString()}] Audit triggered for ${target}`])
      
      // Poll for completion
      const poll = setInterval(async () => {
        try {
          const data = await api.getAudit(res.id)
          setProgress(`Phase: ${data.investigation?.phase ?? 'running'}`)
          const findings = data.investigation?.findings ?? []
          setLogs(prev => [...prev, `[${new Date().toISOString()}] ${findings.length} findings so far...`])
          if (data.investigation?.status === 'completed') {
            clearInterval(poll)
            setResult(data)
            setProgress('Completed')
            setLogs(prev => [...prev, `[${new Date().toISOString()}] ✓ Investigation complete`])
            setTimeout(() => navigate('/findings'), 1500)
          }
        } catch {
          clearInterval(poll)
          setLogs(prev => [...prev, '[poll] Error checking status'])
        }
      }, 3000)
      setTimeout(() => clearInterval(poll), 120000) // max 2 min poll
    } catch (err) {
      setProgress('Failed')
      setLogs(prev => [...prev, `[${new Date().toISOString()}] ERROR: ${err instanceof Error ? err.message : String(err)}`])
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">New Audit</div>
          <div className="page-subtitle">Configure and run a security investigation</div>
        </div>
      </div>
      <div className="page-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          {/* Config */}
          <div>
            <div className="card" style={{ marginBottom: 16 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--gold)' }}>◈ Configuration</h3>
              
              <div className="field" style={{ marginBottom: 12 }}>
                <label className="field-label">Target Path or Project Name</label>
                <input className="input" placeholder="./my-project or profile-name" value={target} onChange={e => setTarget(e.target.value)} />
              </div>

              <div className="card-grid card-grid-2" style={{ marginBottom: 12 }}>
                <div className="field">
                  <label className="field-label">Depth</label>
                  <select className="select" value={depth} onChange={e => setDepth(e.target.value as any)}>
                    <option value="quick">Quick (20 iterations)</option>
                    <option value="full">Full (50 iterations)</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label">Report Format</label>
                  <select className="select" value={format} onChange={e => setFormat(e.target.value)}>
                    <option value="json">JSON</option>
                    <option value="sarif">SARIF 2.1</option>
                    <option value="markdown">Markdown</option>
                  </select>
                </div>
              </div>

              <div className="card-grid card-grid-2" style={{ marginBottom: 16 }}>
                <div className="field">
                  <label className="field-label">AI Model</label>
                  <select className="select" value={model} onChange={e => setModel(e.target.value)}>
                    <option value="mock">Mock (deterministic)</option>
                    <option value="openai">OpenAI (GPT-4o)</option>
                    <option value="anthropic">Anthropic (Claude)</option>
                    <option value="groq">Groq (Llama)</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </div>
                <div className="field">
                  <label className="field-label">Mode</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 8 }}>
                    <input type="checkbox" id="dryrun" checked={dryRun} onChange={e => setDryRun(e.target.checked)} />
                    <label htmlFor="dryrun" style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Dry run (no tools executed)</label>
                  </div>
                </div>
              </div>

              <button className="btn btn-gold" style={{ width: '100%', justifyContent: 'center', padding: '10px 16px' }} onClick={startAudit} disabled={running || !target.trim()}>
                {running ? <><span className="spinner">⟳</span> Running...</> : '▶ Start Investigation'}
              </button>
            </div>

            <div className="alert alert-info">
              <span>ℹ️</span>
              <div>
                <strong>Quick mode</strong> runs 20 iterations for fast results.<br/>
                <strong>Full mode</strong> runs 50 iterations for thorough analysis.<br/>
                <strong>Dry run</strong> plans actions without executing tools.
              </div>
            </div>
          </div>

          {/* Live Output */}
          <div className="card" style={{ fontFamily: 'monospace', fontSize: 12, minHeight: 300 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--gold)' }}>◈ Live Output</h3>
              {running && <span style={{ color: 'var(--success)' }}><span className="spinner">⟳</span> Running</span>}
              {result && <span style={{ color: 'var(--success)' }}>✓ Complete</span>}
            </div>
            <div style={{ background: 'var(--bg)', borderRadius: 4, padding: 12, maxHeight: 400, overflowY: 'auto', lineHeight: 1.6 }}>
              {logs.length === 0 ? (
                <span style={{ color: 'var(--text-muted)' }}>Waiting to start...</span>
              ) : logs.map((log, i) => (
                <div key={i} style={{ color: log.includes('ERROR') ? 'var(--error)' : log.includes('✓') ? 'var(--success)' : 'var(--text-secondary)' }}>
                  {log}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
            {progress && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>{progress}</div>
                <div className="progress-bar">
                  <div className="progress-fill progress-gold" style={{ width: running ? `${Math.min(90, (logs.length % 20) * 5)}%` : '100%' }} />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
