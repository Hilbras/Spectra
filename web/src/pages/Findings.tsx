import { useEffect, useState } from 'react'
import { Search, Filter, Bug, AlertTriangle, Shield } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { api } from '@/hooks/useApi'

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'informational'

const SEVERITY_CONFIG: Record<string, { badge: string; label: string; icon: any }> = {
  critical:    { badge: 'badge-critical', label: 'Critical', icon: AlertTriangle },
  high:        { badge: 'badge-high',     label: 'High',     icon: AlertTriangle },
  medium:      { badge: 'badge-medium',   label: 'Medium',   icon: Shield },
  low:         { badge: 'badge-low',      label: 'Low',      icon: Bug },
  informational: { badge: 'badge-info',   label: 'Info',     icon: Search },
}

export function Findings() {
  const [findings, setFindings] = useState<any[]>([])
  const [audits, setAudits] = useState<any[]>([])
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([api.getFindings(), api.getAudits()])
      .then(([f, a]) => { setFindings(f); setAudits(a) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const counts: Record<string, number> = {}
  findings.forEach((f: any) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1 })

  const filtered = findings
    .filter((f: any) => filter === 'all' || f.severity === filter)
    .filter((f: any) => !search || f.title?.toLowerCase().includes(search.toLowerCase()) || f.category?.toLowerCase().includes(search.toLowerCase()))
    .slice(0, 50)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-3">
          <Shield className="size-8 text-gold-500 animate-spin" style={{ animationDuration: '2s' }} />
          <p className="text-sm text-muted-foreground">Loading findings...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Findings</h1>
          <p className="text-sm text-muted-foreground">{findings.length} vulnerabilities across {audits.length} audits</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-64 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search findings..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 rounded-xl"
          />
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {(['all', 'critical', 'high', 'medium', 'low', 'informational'] as SeverityFilter[]).map((sev) => {
            const count = sev === 'all' ? findings.length : (counts[sev] ?? 0)
            const isActive = filter === sev
            const cfg = SEVERITY_CONFIG[sev]
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-gold-500/20 text-gold-600 dark:text-gold-400 ring-1 ring-gold-500/40'
                    : 'bg-muted text-muted-foreground hover:bg-accent hover:text-foreground'
                }`}
              >
                {cfg?.label ?? sev}
                {count > 0 && <span className={`ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] ${isActive ? 'bg-gold-500/30' : 'bg-background'}`}>{count}</span>}
              </button>
            )
          })}
        </div>
      </div>

      {/* Findings list */}
      {filtered.length === 0 ? (
        <Card className="glass">
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-16 h-16 rounded-2xl bg-green-500/10 flex items-center justify-center mb-4">
              <Shield className="size-8 text-green-500" />
            </div>
            <h3 className="text-base font-semibold">No findings detected</h3>
            <p className="text-sm text-muted-foreground mt-1">
              {filter !== 'all' ? `No ${filter} findings found.` : 'Run your first audit to discover vulnerabilities.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((f: any, i: number) => {
            const cfg = SEVERITY_CONFIG[f.severity] ?? SEVERITY_CONFIG['informational']
            return (
              <Card key={f.id || i} className="glass group hover:border-gold-500/30 transition-all duration-200">
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                      f.severity === 'critical' ? 'bg-red-500/15' :
                      f.severity === 'high' ? 'bg-orange-500/15' :
                      f.severity === 'medium' ? 'bg-yellow-500/15' :
                      f.severity === 'low' ? 'bg-blue-500/15' : 'bg-muted'
                    }`}>
                      {f.severity === 'critical' || f.severity === 'high' ? (
                        <AlertTriangle className="size-4 text-red-500" />
                      ) : f.severity === 'medium' ? (
                        <Shield className="size-4 text-yellow-500" />
                      ) : (
                        <Bug className="size-4 text-blue-500" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                          f.severity === 'critical' ? 'bg-red-500/15 text-red-600 dark:text-red-400' :
                          f.severity === 'high' ? 'bg-orange-500/15 text-orange-600 dark:text-orange-400' :
                          f.severity === 'medium' ? 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400' :
                          f.severity === 'low' ? 'bg-blue-500/15 text-blue-600 dark:text-blue-400' :
                          'bg-muted text-muted-foreground'
                        }`}>
                          {(f.severity ?? 'unknown').toUpperCase()}
                        </span>
                        {f.category && <Badge variant="outline" className="text-xs">{f.category}</Badge>}
                        {f.cwe && <Badge variant="secondary" className="text-xs">CWE-{f.cwe.replace('CWE-', '')}</Badge>}
                      </div>
                      <p className="text-sm font-medium mt-1.5 leading-snug">{f.title}</p>
                      <div className="flex items-center gap-3 mt-1.5 text-[11px] text-muted-foreground">
                        {f.component && <span>· {f.component}</span>}
                        {f.confidence && <span>· {(f.confidence * 100).toFixed(0)}% confidence</span>}
                        {f.auditTarget && <span>· {f.auditTarget}</span>}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
          {findings.length > 50 && (
            <p className="text-center text-xs text-muted-foreground py-4">Showing 50 of {findings.length} findings</p>
          )}
        </div>
      )}
    </div>
  )
}
