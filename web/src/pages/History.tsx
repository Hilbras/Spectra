import { useEffect, useState } from 'react'
import { Search, History, Clock, Trash2 } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/hooks/useApi'

export function AuditHistory() {
  const [audits, setAudits] = useState<any[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getHistory(50).then(setAudits).finally(() => setLoading(false))
  }, [])

  const filtered = audits.filter((a: any) =>
    a.target.toLowerCase().includes(search.toLowerCase())
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Clock className="size-8 text-gold-500 animate-spin" style={{ animationDuration: '2s' }} />
      </div>
    )
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit History</h1>
          <p className="text-sm text-muted-foreground">{audits.length} total audits stored</p>
        </div>
        <div className="relative w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input placeholder="Search targets..." value={search} onChange={e => setSearch(e.target.value)}
            className="pl-9 rounded-xl" />
        </div>
      </div>

      {filtered.length === 0 ? (
        <Card className="glass">
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <History className="size-12 text-muted-foreground/30 mb-4" />
            <h3 className="text-base font-semibold">No history found</h3>
            <p className="text-sm text-muted-foreground mt-1">Run an audit to see results here.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((a: any) => {
            const s = a.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0 }
            const date = new Date(a.generatedAt).toLocaleString()
            const scoreColor = s.overallScore >= 80 ? 'text-green-500' : s.overallScore >= 50 ? 'text-yellow-500' : 'text-red-500'
            return (
              <Card key={a.id || a.generatedAt} className="glass hover:border-gold-500/20 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm ${
                        s.overallScore >= 80 ? 'bg-green-500/10 text-green-500' :
                        s.overallScore >= 50 ? 'bg-yellow-500/10 text-yellow-500' :
                        'bg-red-500/10 text-red-500'
                      }`}>
                        {s.overallScore}
                      </div>
                      <div>
                        <p className="font-medium text-sm">{a.target.split('/').pop() ?? a.target}</p>
                        <p className="text-xs text-muted-foreground">{date} · {a.iterations ?? '?'} iterations · {a.model}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={s.criticalCount > 0 ? 'critical' : s.highCount > 0 ? 'high' : 'success'} className="gap-1">
                        {(s.criticalCount ?? 0) + (s.highCount ?? 0) + (s.mediumCount ?? 0)} findings
                      </Badge>
                      <span className={`text-sm font-bold ${scoreColor}`}>{s.overallScore}/100</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
