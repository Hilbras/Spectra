import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Bug, TrendingUp, Clock, Zap, ArrowUpRight, AlertTriangle,
  CheckCircle2, Activity, Target,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api } from '@/hooks/useApi'

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
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([api.getAudits(), api.getHealth()])
      .then(([data, h]) => { setAudits(data); setHealth(h) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const stats = audits.reduce((acc, a) => {
    const s = a.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0 }
    acc.total++
    acc.scores.push(s.overallScore)
    acc.critical += s.criticalCount
    acc.high += s.highCount
    return acc
  }, { total: 0, scores: [] as number[], critical: 0, high: 0 })

  const avgScore = stats.scores.length ? Math.round(stats.scores.reduce((a, b) => a + b, 0) / stats.scores.length) : 0
  const recentAudits = [...audits].sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime())

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-3">
          <Activity className="size-8 text-gold-500 animate-spin" style={{ animationDuration: '2s' }} />
          <p className="text-sm text-muted-foreground">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Security research overview &amp; recent activity</p>
        </div>
        <Button onClick={() => navigate('/audit')} variant="gold" className="gap-2 rounded-xl">
          <Zap className="size-4" /> New Audit
        </Button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Shield}
          label="Total Audits"
          value={String(stats.total)}
          color="text-gold-500"
          bg="bg-gold-500/10"
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical + High"
          value={String(stats.critical + stats.high)}
          color={stats.critical + stats.high > 0 ? "text-red-500" : "text-green-500"}
          bg={stats.critical + stats.high > 0 ? "bg-red-500/10" : "bg-green-500/10"}
        />
        <StatCard
          icon={TrendingUp}
          label="Average Score"
          value={`${avgScore}/100`}
          color={avgScore >= 80 ? "text-green-500" : avgScore >= 50 ? "text-yellow-500" : "text-red-500"}
          bg={avgScore >= 80 ? "bg-green-500/10" : avgScore >= 50 ? "bg-yellow-500/10" : "bg-red-500/10"}
        />
        <StatCard
          icon={Target}
          label="Version"
          value="0.0.6"
          color="text-gold-500"
          bg="bg-gold-500/10"
        />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent audits */}
        <Card className="lg:col-span-2 glass">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Recent Audits</CardTitle>
                <CardDescription>Last 5 security investigations</CardDescription>
              </div>
              <Button variant="ghost" size="sm" className="text-xs" onClick={() => navigate('/history')}>
                View All <ArrowUpRight className="size-3 ml-1" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {recentAudits.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Shield className="size-12 text-muted-foreground/30 mb-3" />
                <p className="text-sm text-muted-foreground">No audits yet</p>
                <p className="text-xs text-muted-foreground mt-1">Run your first security investigation</p>
                <Button variant="gold" size="sm" className="mt-4 gap-2" onClick={() => navigate('/audit')}>
                  <Zap className="size-3" /> Start Audit
                </Button>
              </div>
            ) : (
              <div className="space-y-3">
                {recentAudits.slice(0, 5).map((a) => {
                  const s = a.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0 }
                  const findings = (a.investigation?.findings ?? []).length
                  const date = new Date(a.generatedAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                  const scoreColor = s.overallScore >= 80 ? 'text-green-500' : s.overallScore >= 50 ? 'text-yellow-500' : 'text-red-500'
                  return (
                    <div key={a.id || a.generatedAt} className="flex items-center justify-between p-3 rounded-xl hover:bg-accent/50 transition-colors cursor-pointer group"
                      onClick={() => navigate('/findings')}>
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${s.overallScore >= 80 ? 'bg-green-500/10 text-green-500' : s.overallScore >= 50 ? 'bg-yellow-500/10 text-yellow-500' : 'bg-red-500/10 text-red-500'}`}>
                          {s.overallScore >= 80 ? <CheckCircle2 className="size-4" /> : <AlertTriangle className="size-4" />}
                        </div>
                        <div>
                          <p className="text-sm font-medium">{a.target.split('/').pop() ?? a.target}</p>
                          <p className="text-xs text-muted-foreground">{date}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className={`text-sm font-bold ${scoreColor}`}>{s.overallScore}</p>
                          <p className="text-[10px] text-muted-foreground">score</p>
                        </div>
                        {findings > 0 && (
                          <Badge variant={s.criticalCount > 0 ? 'critical' : s.highCount > 0 ? 'high' : 'medium'} className="gap-1">
                            <Bug className="size-3" /> {findings}
                          </Badge>
                        )}
                        <ArrowUpRight className="size-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quick actions */}
        <div className="space-y-4">
          <Card className="glass">
            <CardHeader className="pb-3"><CardTitle className="text-base">Quick Actions</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {[
                { href: '/audit', label: 'New Audit', desc: 'Run security investigation', icon: Zap, color: 'text-gold-500' },
                { href: '/findings', label: 'Browse Findings', desc: 'Review vulnerabilities', icon: Bug, color: 'text-red-500' },
                { href: '/benchmarks', label: 'Run Benchmarks', desc: 'Test all fixtures', icon: Activity, color: 'text-blue-500' },
                { href: '/health', label: 'System Health', desc: 'Check installation', icon: Shield, color: 'text-green-500' },
              ].map(({ href, label, desc, icon: Icon, color }) => (
                <button key={href} onClick={() => navigate(href)}
                  className="w-full flex items-center gap-3 p-3 rounded-xl hover:bg-accent/60 transition-all duration-200 text-left group">
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color.replace('text-', 'bg-').replace('-500', '/10')}`}>
                    <Icon className={`size-4 ${color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{label}</p>
                    <p className="text-[11px] text-muted-foreground">{desc}</p>
                  </div>
                  <ArrowUpRight className="size-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-all" />
                </button>
              ))}
            </CardContent>
          </Card>

          {/* Score overview */}
          <Card className="glass">
            <CardHeader className="pb-3"><CardTitle className="text-base">Security Score</CardTitle></CardHeader>
            <CardContent>
              <div className="flex items-center justify-center py-4">
                <div className="relative w-28 h-28">
                  <svg className="w-full h-full" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="8" className="text-muted/20" />
                    <circle cx="50" cy="50" r="42" fill="none" strokeWidth="8" strokeLinecap="round"
                      className={`${avgScore >= 80 ? 'text-green-500' : avgScore >= 50 ? 'text-yellow-500' : 'text-red-500'}`}
                      stroke="currentColor"
                      strokeDasharray={`${avgScore * 2.64} ${264 - avgScore * 2.64}`}
                      transform="rotate(-90 50 50)"
                      style={{ transition: 'stroke-dasharray 0.8s ease' }}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className={`text-3xl font-bold ${avgScore >= 80 ? 'text-green-500' : avgScore >= 50 ? 'text-yellow-500' : 'text-red-500'}`}>
                      {avgScore}
                    </span>
                  </div>
                </div>
              </div>
              <p className="text-center text-xs text-muted-foreground mt-2">Across {stats.total} audit{stats.total !== 1 ? 's' : ''}</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, color, bg }: { icon: any; label: string; value: string; color: string; bg: string }) {
  return (
    <Card className="glass">
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-xs text-muted-foreground mt-1">{label}</p>
          </div>
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${bg}`}>
            <Icon className={`size-5 ${color}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
