import { useEffect, useState } from 'react'
import { Plus, Trash2, FolderOpen } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/hooks/useApi'

export function Projects() {
  const [profiles, setProfiles] = useState<Record<string, any>>({})
  const [adding, setAdding] = useState(false)
  const [name, setName] = useState('')
  const [path, setPath] = useState('')

  useEffect(() => {
    api.getConfig().then((cfg: any) => setProfiles(cfg.profiles ?? {}))
  }, [])

  async function addProject() {
    if (!name.trim() || !path.trim()) return
    await api.updateConfig({ profiles: { ...profiles, [name]: { path } } })
    setProfiles({ ...profiles, [name]: { path } })
    setName(''); setPath(''); setAdding(false)
  }

  async function removeProject(key: string) {
    const next = { ...profiles }; delete next[key]
    await api.updateConfig({ profiles: next })
    setProfiles(next)
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Projects</h1>
          <p className="text-sm text-muted-foreground">Manage saved project profiles for quick auditing</p>
        </div>
        <Button onClick={() => setAdding(!adding)} variant="gold" className="gap-2 rounded-xl">
          <Plus className="size-4" /> Add Project
        </Button>
      </div>

      {adding && (
        <Card className="glass border-gold-500/30">
          <CardHeader><CardTitle className="text-base">Add New Project</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Profile Name</label>
                <Input placeholder="my-app" value={name} onChange={e => setName(e.target.value)} className="rounded-xl" />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Project Path</label>
                <Input placeholder="/path/to/project" value={path} onChange={e => setPath(e.target.value)} className="rounded-xl" />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => { setAdding(false); setName(''); setPath('') }}>Cancel</Button>
              <Button variant="gold" size="sm" onClick={addProject}>Save Project</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {Object.keys(profiles).length === 0 ? (
        <Card className="glass">
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <FolderOpen className="size-12 text-muted-foreground/30 mb-4" />
            <h3 className="text-base font-semibold">No projects configured</h3>
            <p className="text-sm text-muted-foreground mt-1">Add a project to run audits with a single click.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(profiles).map(([key, proj]: [string, any]) => (
            <Card key={key} className="glass group hover:border-gold-500/30 transition-all">
              <CardContent className="p-4 relative">
                <button onClick={() => removeProject(key)}
                  className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded-lg hover:bg-red-500/10">
                  <Trash2 className="size-3.5 text-red-500" />
                </button>
                <div className="w-10 h-10 rounded-xl bg-gold-500/10 flex items-center justify-center mb-3">
                  <FolderOpen className="size-5 text-gold-500" />
                </div>
                <p className="font-semibold text-sm truncate">{key}</p>
                <p className="text-xs text-muted-foreground mt-1 truncate">{proj.path}</p>
                <p className="text-[11px] text-muted-foreground mt-2">
                  {proj.lastAudit ? `Last: ${new Date(proj.lastAudit).toLocaleDateString()}` : 'No audits yet'}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
