import { useEffect, useState } from 'react'
import { api } from '../hooks/useApi'

export function Health() {
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getHealth().then(setHealth).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="page-body"><div className="empty-state"><div className="icon">🔄</div><p>Checking health...</p></div></div>

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">System Health</div>
          <div className="page-subtitle">Installation diagnostics and environment info</div>
        </div>
      </div>
      <div className="page-body">
        <div className="card" style={{ marginBottom: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--gold)' }}>◈ Environment</h3>
          <table className="table">
            <tbody>
              <tr><td>Node.js</td><td>{health?.nodeVersion}{parseInt(health?.nodeVersion?.split('.')[0] ?? '0') >= 20 ? ' ✓' : ' ✗ (need >= 20)'}</td></tr>
              <tr><td>npm</td><td>{health?.npmVersion}</td></tr>
              <tr><td>Spectra binary</td><td>{health?.binPath ? `✓ ${health.binPath}` : <span style={{ color: 'var(--error)' }}>Not found</span>}</td></tr>
              <tr><td>Version</td><td>{health?.version}</td></tr>
              <tr><td>Theme</td><td>{health?.theme}</td></tr>
              <tr><td>Config</td><td>{health?.configExists ? '✓ ~/.spectra/config.json' : <span style={{ color: 'var(--warning)' }}>Missing — run 'spectra init'</span>}</td></tr>
            </tbody>
          </table>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--gold)' }}>◈ Dependencies</h3>
          <table className="table">
            <tbody>
              <tr><td>Docker</td><td>{health?.dockerAvailable ? '✓ Available' : <span style={{ color: 'var(--warning)' }}>Not installed (sandbox fallback enabled)</span>}</td></tr>
              <tr><td>TypeScript</td><td>✓ Bundled</td></tr>
            </tbody>
          </table>
        </div>

        {(health?.issues?.length || health?.warnings?.length) && (
          <div>
            {health.issues?.map((i: string, idx: number) => (
              <div key={idx} className="alert alert-error">❌ {i}</div>
            ))}
            {health.warnings?.map((w: string, idx: number) => (
              <div key={idx} className="alert alert-warning">⚠ {w}</div>
            ))}
          </div>
        )}
        {!health?.issues?.length && !health?.warnings?.length && (
          <div className="alert alert-success">✓ Everything looks healthy!</div>
        )}
      </div>
    </div>
  )
}
