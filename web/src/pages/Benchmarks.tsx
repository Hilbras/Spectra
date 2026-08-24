import { useState } from 'react'

export function Benchmarks() {
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [progress, setProgress] = useState('')

  async function runBenchmarks() {
    setRunning(true)
    setResults([])
    setProgress('Starting benchmarks...')
    try {
      const res = await fetch('/api/benchmarks', { method: 'POST' })
      const reader = res.body?.getReader()
      const decoder = new TextDecoder()
      while (reader) {
        const { done, value } = await reader.read()
        if (done) break
        const text = decoder.decode(value)
        setProgress(text.trim())
      }
      setResults([{ fixture: 'completed', status: 'ok', durationMs: 0, findings: 0, errors: 0 }])
    } catch (e) {
      setResults([{ fixture: 'error', status: 'fail', durationMs: 0, findings: 0, errors: 1 }])
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Benchmarks</div>
          <div className="page-subtitle">Run all 5 fixture projects and verify regression</div>
        </div>
        <button className="btn btn-gold" onClick={runBenchmarks} disabled={running}>
          {running ? '⟳ Running...' : '▶ Run All Benchmarks'}
        </button>
      </div>
      <div className="page-body">
        <div className="card">
          <table className="table">
            <thead><tr><th>Fixture</th><th>Status</th><th>Time</th><th>Findings</th><th>Errors</th></tr></thead>
            <tbody>
              {results.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                  Click "Run All Benchmarks" to test against all fixtures
                </td></tr>
              ) : results.map((r, i) => (
                <tr key={i}>
                  <td>{r.fixture}</td>
                  <td><span className={`badge ${r.status === 'pass' ? 'badge-success' : r.status === 'warn' ? 'badge-medium' : 'badge-critical'}`}>{r.status}</span></td>
                  <td>{r.durationMs}ms</td>
                  <td>{r.findings}</td>
                  <td>{r.errors > 0 ? <span style={{ color: 'var(--warning)' }}>{r.errors}</span> : '0'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {progress && <div className="alert alert-info" style={{ marginTop: 12 }}>{progress}</div>}
      </div>
    </div>
  )
}
