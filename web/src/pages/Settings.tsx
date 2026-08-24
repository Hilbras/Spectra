import { useEffect, useState } from 'react'
import { api } from '../hooks/useApi'
import { useTheme } from '../hooks/useTheme'

export function Settings() {
  const { themeName, setTheme } = useTheme()
  const [config, setConfig] = useState<any>({})

  useEffect(() => {
    api.getConfig().then(setConfig).catch(() => {})
  }, [])

  async function save(field: string, value: unknown) {
    setSaving(true)
    await api.updateConfig({ [field]: value })
    setConfig((prev: any) => ({ ...prev, [field]: value }))
    setSaving(false)
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">Configure Spectra preferences</div>
        </div>
      </div>
      <div className="page-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          {/* Appearance */}
          <div className="card">
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--gold)' }}>◈ Appearance</h3>
            <div className="field" style={{ marginBottom: 12 }}>
              <label className="field-label">Theme</label>
              <select className="select" value={themeName} onChange={e => setTheme(e.target.value as any)}>
                <option value="dark">Dark (Gold accent)</option>
                <option value="light">Light (Gold accent)</option>
              </select>
            </div>
            <div className="alert alert-gold" style={{ fontSize: 12 }}>
              Gold is Spectra's signature accent color, used on borders, headers, and key UI elements.
            </div>
          </div>

          {/* Default Behavior */}
          <div className="card">
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--gold)' }}>◈ Defaults</h3>
            <div className="field" style={{ marginBottom: 12 }}>
              <label className="field-label">Default Model</label>
              <select className="select" value={config.defaultModel ?? 'mock'} onChange={e => save('defaultModel', e.target.value)}>
                <option value="mock">Mock (offline testing)</option>
                <option value="openai">OpenAI GPT-4o</option>
                <option value="anthropic">Anthropic Claude</option>
                <option value="groq">Groq (Llama)</option>
                <option value="ollama">Ollama (local)</option>
              </select>
            </div>
            <div className="field" style={{ marginBottom: 12 }}>
              <label className="field-label">Default Report Format</label>
              <select className="select" value={config.defaultFormat ?? 'json'} onChange={e => save('defaultFormat', e.target.value)}>
                <option value="json">JSON</option>
                <option value="sarif">SARIF 2.1</option>
                <option value="markdown">Markdown</option>
              </select>
            </div>
            <div className="field">
              <label className="field-label">Auto-Approve Threshold</label>
              <select className="select" value={config.autoApproveThreshold ?? 'medium'} onChange={e => save('autoApproveThreshold', e.target.value)}>
                <option value="low">Low (approve all)</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
          </div>

          {/* API Keys */}
          <div className="card" style={{ gridColumn: '1 / -1' }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--gold)' }}>◈ API Keys</h3>
            <div className="card-grid card-grid-2">
              {['openai', 'anthropic', 'groq', 'ollama'].map((provider) => {
                const hasKey = !!(config.apiKeys?.[provider])
                return (
                  <div key={provider} className="field">
                    <label className="field-label">{provider.charAt(0).toUpperCase() + provider.slice(1)}</label>
                    <input className="input" type="password" placeholder={hasKey ? '••••••••••••' : 'Enter API key...'} defaultValue={hasKey ? '' : ''} />
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{hasKey ? '✓ Configured' : 'Not set — use mock model'}</span>
                  </div>
                )
              })}
            </div>
            <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }} onClick={() => save('apiKeys', config.apiKeys ?? {})}>Save Keys</button>
          </div>
        </div>
      </div>
    </div>
  )
}
