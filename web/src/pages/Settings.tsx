import { useEffect, useState } from 'react'
import { Palette, Key, Globe, Database } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTheme } from '@/components/theme-provider'
import { api } from '@/hooks/useApi'

export function Settings() {
  const { theme, setTheme } = useTheme()
  const [config, setConfig] = useState<any>({})
  const [saving, setSaving] = useState(false)

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
    <div className="space-y-6 fade-in">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Configure Spectra preferences and integrations</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Appearance */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Palette className="size-5 text-gold-500" />
              <CardTitle className="text-base">Appearance</CardTitle>
            </div>
            <CardDescription>Customize the visual theme</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-3">
              {(['dark', 'light'] as const).map((t) => (
                <button key={t} onClick={() => setTheme(t)}
                  className={`flex-1 p-4 rounded-xl border-2 transition-all duration-200 ${
                    theme === t ? 'border-gold-500 bg-gold-500/10' : 'border-border hover:border-gold-500/40'
                  }`}>
                  <div className={`w-8 h-8 rounded-lg mx-auto mb-2 ${t === 'dark' ? 'bg-gray-900' : 'bg-white border border-gray-200'}`} />
                  <span className="text-sm font-medium capitalize">{t} theme</span>
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground text-center">
              Gold accent color is used throughout the interface.
            </p>
          </CardContent>
        </Card>

        {/* Defaults */}
        <Card className="glass">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Database className="size-5 text-gold-500" />
              <CardTitle className="text-base">Default Behavior</CardTitle>
            </div>
            <CardDescription>Default settings for new audits</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Default AI Model</label>
              <select value={config.defaultModel ?? 'mock'} onChange={e => save('defaultModel', e.target.value)}
                className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-gold-500/40">
                <option value="mock">Mock (testing)</option>
                <option value="openai">OpenAI GPT-4o</option>
                <option value="anthropic">Anthropic Claude</option>
                <option value="groq">Groq Llama</option>
                <option value="ollama">Ollama (local)</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Report Format</label>
              <select value={config.defaultFormat ?? 'json'} onChange={e => save('defaultFormat', e.target.value)}
                className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-gold-500/40">
                <option value="json">JSON</option>
                <option value="sarif">SARIF 2.1</option>
                <option value="markdown">Markdown</option>
              </select>
            </div>
          </CardContent>
        </Card>

        {/* API Keys */}
        <Card className="glass lg:col-span-2">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Key className="size-5 text-gold-500" />
              <CardTitle className="text-base">API Keys</CardTitle>
            </div>
            <CardDescription>Configure AI provider credentials</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {['openai', 'anthropic', 'groq', 'ollama'].map((provider) => {
                const hasKey = !!config.apiKeys?.[provider]
                return (
                  <div key={provider} className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Globe className="size-3.5 text-muted-foreground" />
                      <label className="text-sm font-medium capitalize">{provider}</label>
                      {hasKey && <span className="text-xs text-green-500">✓</span>}
                    </div>
                    <Input
                      type="password"
                      placeholder={hasKey ? '••••••••••••' : `Enter ${provider} API key...`}
                      className="rounded-xl"
                    />
                  </div>
                )
              })}
            </div>
            <Button variant="outline" size="sm" className="mt-4" onClick={() => save('apiKeys', config.apiKeys ?? {})}>
              {saving ? 'Saving...' : 'Save API Keys'}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
