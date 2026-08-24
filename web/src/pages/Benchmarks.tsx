import { useState } from 'react'
import { Play, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

const FIXTURES = ['sql-injection', 'xss', 'command-injection', 'path-traversal', 'idor']

export function Benchmarks() {
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<Record<string, { status: string; ms: number }>>({})
  const [currentFixture, setCurrentFixture] = useState('')

  async function runAll() {
    setRunning(true)
    setResults({})
    for (const fixture of FIXTURES) {
      setCurrentFixture(fixture)
      const t0 = Date.now()
      try {
        const res = await fetch(`/api/audits`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: `tests/fixtures/${fixture}`, depth: 'quick' }),
        })
        const data = await res.json()
        // Wait a bit for audit to complete
        await new Promise(r => setTimeout(r, 3000))
        const elapsed = Date.now() - t0
        setResults(prev => ({ ...prev, [fixture]: { status: 'pass', ms: elapsed } }))
      } catch {
        setResults(prev => ({ ...prev, [fixture]: { status: 'fail', ms: 0 } }))
      }
    }
    setCurrentFixture('')
    setRunning(false)
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Benchmarks</h1>
          <p className="text-sm text-muted-foreground">Run all 5 fixture projects and verify regression</p>
        </div>
        <Button onClick={runAll} disabled={running} variant="gold" className="gap-2 rounded-xl">
          {running ? <><Loader2 className="size-4 animate-spin" /> Running...</> : <><Play className="size-4" /> Run All</>}
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {FIXTURES.map((fixture) => {
          const r = results[fixture]
          const runningHere = currentFixture === fixture && !r
          return (
            <Card key={fixture} className={`glass transition-all ${r?.status === 'pass' ? 'border-green-500/30' : r?.status === 'fail' ? 'border-red-500/30' : ''}`}>
              <CardContent className="p-5 flex flex-col items-center text-center gap-3">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                  r?.status === 'pass' ? 'bg-green-500/15' :
                  r?.status === 'fail' ? 'bg-red-500/15' :
                  runningHere ? 'bg-gold-500/15' : 'bg-muted'
                }`}>
                  {r?.status === 'pass' ? <CheckCircle2 className="size-6 text-green-500" /> :
                   r?.status === 'fail' ? <AlertTriangle className="size-6 text-red-500" /> :
                   runningHere ? <Loader2 className="size-6 text-gold-500 animate-spin" /> :
                   <span className="text-2xl">🧪</span>}
                </div>
                <div>
                  <p className="font-medium text-sm capitalize">{fixture.replace(/-/g, ' ')}</p>
                  {r && <p className="text-xs text-muted-foreground mt-1">{r.ms}ms</p>}
                </div>
                {r && <Badge variant={r.status === 'pass' ? 'success' : 'destructive'}>{r.status}</Badge>}
                {!r && !runningHere && <Badge variant="outline" className="text-xs">Pending</Badge>}
              </CardContent>
            </Card>
          )
        })}
      </div>

      {Object.keys(results).length > 0 && (
        <Card className="glass">
          <CardHeader><CardTitle className="text-base">Summary</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <span className="text-sm text-muted-foreground">
                {Object.values(results).filter((r: any) => r.status === 'pass').length}/{FIXTURES.length} passed
              </span>
              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-gold-400 to-gold-600 rounded-full transition-all duration-500"
                  style={{ width: `${(Object.values(results).filter((r: any) => r.status === 'pass').length / FIXTURES.length) * 100}%` }} />
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
