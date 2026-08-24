interface Phase {
  name: string
  short: string
  completed: boolean
  current: boolean
}

interface AuditTimelineProps {
  phases: Phase[]
  currentPhase?: string
}

const PHASE_ORDER = [
  'INITIALIZATION', 'RECONNAISSANCE', 'ARCHITECTURE_ANALYSIS', 'ATTACK_SURFACE_MAPPING',
  'SOURCE_ANALYSIS', 'DEPENDENCY_ANALYSIS', 'CONFIGURATION_ANALYSIS', 'SECRET_ANALYSIS',
  'AUTHENTICATION_ANALYSIS', 'AUTHORIZATION_ANALYSIS', 'API_ANALYSIS', 'BUSINESS_LOGIC_ANALYSIS',
  'HYPOTHESIS_GENERATION', 'INVESTIGATION', 'VALIDATION', 'EVIDENCE_COLLECTION',
  'FINDING_CORRELATION', 'RISK_ASSESSMENT', 'REPORTING', 'COMPLETION',
]

export function AuditTimeline({ phases, currentPhase }: AuditTimelineProps) {
  const completed = new Set(phases.map(p => p.name))
  const currentIndex = currentPhase ? PHASE_ORDER.indexOf(currentPhase.toUpperCase()) : -1
  
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
      {PHASE_ORDER.map((name, i) => {
        const isCompleted = completed.has(name) || i < currentIndex
        const isCurrent = name.toUpperCase() === currentPhase?.toUpperCase()
        const color = isCurrent ? 'var(--gold)' : isCompleted ? 'var(--success)' : 'var(--text-muted)'
        return (
          <div
            key={name}
            title={name.replace(/_/g, ' ')}
            style={{
              width: 8, height: 8, borderRadius: '50%',
              background: color, opacity: isCurrent ? 1 : isCompleted ? 0.8 : 0.3,
              flexShrink: 0,
            }}
          />
        )
      })}
    </div>
  )
}
