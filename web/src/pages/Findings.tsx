import { useEffect, useState } from 'react'
import { api } from '../hooks/useApi'
import { FindingCard } from '../components/FindingCard'

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'informational'

export function Findings() {
  const [findings, setFindings] = useState<any[]>([])
  const [audits, setAudits] = useState<any[]>([])
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([api.getFindings(), api.getAudits()])
      .then(([f, a]) => { setFindings(f); setAudits(a) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filtered = filter === 'all' ? findings : findings.filter((f: any) => f.severity === filter)
  const counts: Record<string, number> = {}
  findings.forEach((f: any) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1 })

  if (loading) return <div className="page-body"><div className="empty-state"><div className="icon">🔄</div><p>Loading...</p></div></div>

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Findings</div>
          <div className="page-subtitle">{findings.length} vulnerabilities detected across {audits.length} audits</div>
        </div>
      </div>
      <div className="page-body">
        {/* Filter chips */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
          {[
            { key: 'all', label: 'All', count: findings.length },
            { key: 'critical', label: 'Critical', count: counts.critical ?? 0 },
            { key: 'high', label: 'High', count: counts.high ?? 0 },
            { key: 'medium', label: 'Medium', count: counts.medium ?? 0 },
            { key: 'low', label: 'Low', count: counts.low ?? 0 },
          ].map(({ key, label, count }) => (
            <button
              key={key}
              className={`btn ${filter === key ? 'btn-primary' : ''}`}
              style={{ gap: 6 }}
              onClick={() => setFilter(key as SeverityFilter)}
            >
              {label}
              {count > 0 && <span className="badge" style={{ background: 'var(--bg-tertiary)', fontSize: 10 }}>{count}</span>}
            </button>
          ))}
        </div>

        {/* Findings list */}
        {filtered.length === 0 ? (
          <div className="empty-state">
            <div className="icon">{filter === 'all' ? '🎉' : '🎯'}</div>
            <p>{filter === 'all' ? 'No findings yet. Run your first audit!' : `No ${filter} findings found.`}</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {filtered.slice(0, 50).map((f: any) => (
              <FindingCard key={f.id} finding={f} />
            ))}
            {filtered.length > 50 && (
              <div style={{ textAlign: 'center', padding: 16, color: 'var(--text-muted)', fontSize: 13 }}>
                Showing 50 of {filtered.length} findings
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
