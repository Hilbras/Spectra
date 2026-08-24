import { useEffect, useState } from 'react'
import { Server, Cpu, HardDrive, Wifi, CheckCircle2, AlertCircle, XCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { api } from '@/hooks/useApi'

export function Health() {
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getHealth().then(setData).finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Server className="size-8 text-gold-500 animate-spin" style={{ animationDuration: '2s' }} />
      </div>
    )
  }

  const checks = [
    { label: 'Node.js', value: data?.nodeVersion, ok: parseInt(data?.nodeVersion?.split('.')[0] ?? '0') >= 20, icon: Cpu },
    { label: 'npm', value: data?.npmVersion, ok: !!data?.npmVersion, icon: HardDrive },
    { label: 'Spectra binary', value: data?.binPath, ok: !!data?.binPath, icon: Server },
    { label: 'Config file', value: '~/.spectra/config.json', ok: data?.configExists, icon: CheckCircle2 },
    { label: 'Docker', value: data?.dockerAvailable ? 'available' : 'not installed', ok: data?.dockerAvailable, icon: Wifi },
  ]

  return (
    <div className="space-y-6 fade-in">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">System Health</h1>
        <p className="text-sm text-muted-foreground">Installation diagnostics and environment check</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="glass">
          <CardHeader><CardTitle className="text-base">Environment</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {checks.map(({ label, value, ok, icon: Icon }) => (
              <div key={label} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${ok ? 'bg-green-500/10' : 'bg-red-500/10'}`}>
                    <Icon className={`size-4 ${ok ? 'text-green-500' : 'text-red-500'}`} />
                  </div>
                  <span className="text-sm font-medium">{label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">{value}</span>
                  {ok ? <Badge variant="success" className="text-xs">OK</Badge> : <Badge variant="destructive" className="text-xs">MISSING</Badge>}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="glass">
          <CardHeader><CardTitle className="text-base">Issues & Warnings</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {(data?.issues ?? []).map((i: string, idx: number) => (
              <div key={idx} className="flex items-start gap-3 p-3 rounded-xl bg-red-500/10 border border-red-500/20">
                <XCircle className="size-4 text-red-500 shrink-0 mt-0.5" />
                <span className="text-sm text-red-600 dark:text-red-400">{i}</span>
              </div>
            ))}
            {(data?.warnings ?? []).map((w: string, idx: number) => (
              <div key={idx} className="flex items-start gap-3 p-3 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
                <AlertCircle className="size-4 text-yellow-500 shrink-0 mt-0.5" />
                <span className="text-sm text-yellow-700 dark:text-yellow-400">{w}</span>
              </div>
            ))}
            {(!data?.issues?.length && !data?.warnings?.length) && (
              <div className="flex items-center gap-3 p-4 rounded-xl bg-green-500/10 border border-green-500/20">
                <CheckCircle2 className="size-5 text-green-500" />
                <span className="text-sm text-green-600 dark:text-green-400">Everything looks healthy!</span>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
