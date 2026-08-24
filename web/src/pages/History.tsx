import { useEffect, useState } from 'react'
import { api } from '../hooks/useApi'

export function History() {
  const [audits, setAudits] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.getHistory(50).then(setAudits).finally(() => setLoading(false))
  }, [])

  const filtered = audits.filter((a: any) => 
    a.target.toLowerCase().includes(search.toLowerCase()) ||
    (a.summary?.topRisks ?? []).some((r: any) => r.title?.toLowerCase().includes(search.toLowerCase()))
  )

  if (loading) return <div className="page-body"><div className="empty-state"><div className="icon">🔄</div><p>Loading history...</p></div></div>

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Audit History</div>
          <div className="page-subtitle">{audits.length} total audits stored</div>
        </div>
        <input className="input" placeholder="Search..." style={{ width: 200 }} value={search} onChange={e => setSearch(e.target.value)} />
      </div>
      <div className="page-body">
        {filtered.length === 0 ? (
          <div className="empty-state"><div className="icon">📭</div><p>No audit history found.</p></div>
        ) : (
          <div className="card">
            <table className="table">
              <thead>
                <tr><th>Date</th><th>Target</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Iterations</th><th>Status</th></tr>
              </thead>
              <tbody>
                {filtered.map((a: any) => {
                  const s = a.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0, mediumCount: 0 }
                  const date = new Date(a.generatedAt).toLocaleString()
                  const scoreColor = s.overallScore >= 80 ? 'var(--success)' : s.overallScore >= 50 ? 'var(--warning)' : 'var(--error)'
                  return (
                    <tr key={a.id || a.generatedAt}>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{date}</td>
                      <td style={{ fontWeight: 500 }}>{a.target.split('/').pop() ?? a.target}</td>
                      <td><span style={{ color: scoreColor, fontWeight: 600 }}>{s.overallScore}</span></td>
                      <td>{s.criticalCount > 0 ? <span style={{ color: 'var(--error)' }}>{s.criticalCount}</span> : '—'}</td>
                      <td>{s.highCount > 0 ? <span style={{ color: 'var(--high)' }}>{s.highCount}</span> : '—'}</td>
                      <td>{s.mediumCount > 0 ? <span style={{ color: 'var(--warning)' }}>{s.mediumCount}</span> : '—'}</td>
                      <td>{a.iterations ?? '?'}</td>
                      <td><span className="badge badge-success">✓</span></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
