import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../hooks/useApi'

interface AuditSummary {
  id: string
  target: string
  generatedAt: string
  summary?: { overallScore: number; criticalCount: number; highCount: number; mediumCount: number; lowCount: number }
  investigation?: { findings: any[]; hypotheses: any[]; status: string }
}

export function Dashboard() {
  const navigate = useNavigate()
  const [audits, setAudits] = useState<AuditSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [health, setHealth] = useState<any>(null)

  useEffect(() => {
    Promise.all([api.getAudits(), api.getHealth()])
      .then(([data, h]) => { setAudits(data); setHealth(h) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const stats = audits.reduce((acc, a) => {
    const s = a.summary
    if (!s) return acc
    acc.total++
    acc.scores.push(s.overallScore)
    acc.critical += s.criticalCount
    acc.high += s.highCount
    return acc
  }, { total: 0, scores: [] as number[], critical: 0, high: 0 })

  const avgScore = stats.scores.length ? Math.round(stats.scores.reduce((a,b) => a+b, 0) / stats.scores.length) : 0

  if (loading) return (
    <div className="page-body">
      <div className="empty-state"><div className="icon">🔄</div><p>Loading...</p></div>
    </div>
  )

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Security research overview</div>
        </div>
        <button className="btn btn-gold" onClick={() => navigate('/audit')}>
          ▶ New Audit
        </button>
      </div>
      <div className="page-body">
        {/* Stats row */}
        <div className="card-grid card-grid-4" style={{ marginBottom: 20 }}>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--gold)' }}>{stats.total}</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Total Audits</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: stats.critical > 0 ? 'var(--error)' : 'var(--success)' }}>
              {stats.critical + stats.high}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Critical + High</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: avgScore >= 80 ? 'var(--success)' : avgScore >= 50 ? 'var(--warning)' : 'var(--error)' }}>
              {avgScore}/100
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Avg Score</div>
          </div>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--accent)' }}>
              {health?.version || 'v0.0.6'}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Spectra Version</div>
          </div>
        </div>

        {/* Recent audits */}
        <div className="card" style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontSize: 14, fontWeight: 600 }}>Recent Audits</h3>
            <button className="btn btn-sm" onClick={() => navigate('/history')}>View All</button>
          </div>
          {audits.length === 0 ? (
            <div className="empty-state" style={{ padding: '32px' }}>
              <div className="icon">📭</div>
              <p>No audits yet. Start your first security investigation.</p>
              <button className="btn btn-gold" style={{ marginTop: 12 }} onClick={() => navigate('/audit')}>
                ▶ Run First Audit
              </button>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Target</th><th>Date</th><th>Score</th><th>Findings</th><th>Status</th><th></th>
                </tr>
              </thead>
              <tbody>
                {audits.slice(0, 5).map((a) => {
                  const s = a.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0 }
                  const findings = (a.investigation?.findings ?? []).length
                  const date = new Date(a.generatedAt).toLocaleString()
                  const scoreColor = s.overallScore >= 80 ? 'var(--success)' : s.overallScore >= 50 ? 'var(--warning)' : 'var(--error)'
                  return (
                    <tr key={a.id}>
                      <td style={{ fontWeight: 500 }}>{a.target.split('/').pop() ?? a.target}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{date}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div className="progress-bar" style={{ width: 60 }}>
                            <div className="progress-fill" style={{ width: `${s.overallScore}%`, background: scoreColor }} />
                          </div>
                          <span style={{ fontSize: 12, color: scoreColor, fontWeight: 600 }}>{s.overallScore}</span>
                        </div>
                      </td>
                      <td>
                        {findings > 0 ? (
                          <span style={{ color: s.criticalCount > 0 ? 'var(--error)' : 'var(--warning)', fontWeight: 600 }}>{findings}</span>
                        ) : <span style={{ color: 'var(--success)' }}>0</span>}
                      </td>
                      <td><span className="badge badge-success">✓ Completed</span></td>
                      <td>
                        <button className="btn btn-sm" onClick={() => navigate(`/findings`)}>View</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Quick actions */}
        <div className="card-grid card-grid-3">
          <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/audit')}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>🔍</div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>New Audit</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Run security investigation on a project</div>
          </div>
          <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/findings')}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>📊</div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Browse Findings</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Review all detected vulnerabilities</div>
          </div>
          <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/benchmarks')}>
            <div style={{ fontSize: 24, marginBottom: 8 }}>🧪</div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Run Benchmarks</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Test against all fixture projects</div>
          </div>
        </div>
      </div>
    </div>
  )
}
