import { useEffect, useState } from 'react'
import { api } from '../hooks/useApi'

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
    setName('')
    setPath('')
    setAdding(false)
  }

  async function removeProject(key: string) {
    const next = { ...profiles }
    delete next[key]
    await api.updateConfig({ profiles: next })
    setProfiles(next)
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Projects</div>
          <div className="page-subtitle">Manage saved project profiles for quick auditing</div>
        </div>
        <button className="btn btn-gold" onClick={() => setAdding(!adding)}>+ Add Project</button>
      </div>
      <div className="page-body">
        {adding && (
          <div className="card" style={{ marginBottom: 16 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--gold)' }}>Add Project</h3>
            <div className="card-grid card-grid-2">
              <div className="field">
                <label className="field-label">Profile Name</label>
                <input className="input" placeholder="my-app" value={name} onChange={e => setName(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label">Project Path</label>
                <input className="input" placeholder="/path/to/project" value={path} onChange={e => setPath(e.target.value)} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="btn btn-primary btn-sm" onClick={addProject}>Save</button>
              <button className="btn btn-sm" onClick={() => { setAdding(false); setName(''); setPath('') }}>Cancel</button>
            </div>
          </div>
        )}

        {Object.keys(profiles).length === 0 ? (
          <div className="empty-state">
            <div className="icon">📁</div>
            <p>No projects configured. Add a project to run audits with a single click.</p>
          </div>
        ) : (
          <div className="card-grid card-grid-3">
            {Object.entries(profiles).map(([key, proj]: [string, any]) => (
              <div key={key} className="card" style={{ position: 'relative' }}>
                <button className="btn btn-sm" style={{ position: 'absolute', top: 8, right: 8 }} onClick={() => removeProject(key)}>✕</button>
                <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 4 }}>{key}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{proj.path}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {proj.lastAudit ? `Last: ${new Date(proj.lastAudit).toLocaleDateString()}` : 'No audits yet'}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
