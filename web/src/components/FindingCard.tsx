import type { Finding } from '../types'

interface FindingCardProps {
  finding: Finding
  onClick?: () => void
}

const severityColor = (sev: string) => {
  const map: Record<string, string> = {
    critical: '#ff3333', high: '#f85149', medium: '#d29922', low: '#58a6ff', informational: '#8b949e'
  }
  return map[sev] ?? '#8b949e'
}

const severityLabel = (sev: string) => {
  const map: Record<string, string> = {
    critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', informational: 'INFO'
  }
  return map[sev] ?? sev.toUpperCase()
}

export function FindingCard({ finding, onClick }: FindingCardProps) {
  const color = severityColor(finding.severity)
  return (
    <div className="card fade-in" style={{ borderLeft: `3px solid ${color}`, cursor: onClick ? 'pointer' : 'default' }} onClick={onClick}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <span className="badge" style={{ background: `${color}20`, color, minWidth: 60, justifyContent: 'center' }}>
          {severityLabel(finding.severity)}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 500, fontSize: 13, marginBottom: 4 }}>{finding.title}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {finding.category && <span>{finding.category} · </span>}
            {finding.component && <span>{finding.component} · </span>}
            {finding.confidence && <span>{(finding.confidence * 100).toFixed(0)}% confidence</span>}
          </div>
          {finding.cwe && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              CWE-{finding.cwe.replace('CWE-', '')}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
