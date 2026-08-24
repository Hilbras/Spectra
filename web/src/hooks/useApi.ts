const API_BASE = '/api'

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`)
  return res.json()
}

export const api = {
  getAudits: () => request<any[]>('/audits'),
  getAudit: (id: string) => request<any>(`/audits/${id}`),
  triggerAudit: (target: string, opts?: Record<string, unknown>) => 
    request<{ id: string }>('/audits', { method: 'POST', body: JSON.stringify({ target, ...opts }) }),
  getFindings: (filters?: { severity?: string; limit?: number }) => 
    request<any[]>('/findings' + (filters ? '?' + new URLSearchParams(filters as any).toString() : '')),
  getHistory: (limit?: number) => request<any[]>(`/history?limit=${limit ?? 20}`),
  getConfig: () => request<any>('/config'),
  updateConfig: (patch: Record<string, unknown>) => 
    request<any>('/config', { method: 'PUT', body: JSON.stringify(patch) }),
  getHealth: () => request<any>('/health'),
  deleteAudit: (id: string) => request<any>(`/audits/${id}`, { method: 'DELETE' }),
}
