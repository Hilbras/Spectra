/**
 * Hilbras Spectra — Web Server
 * 
 * Express server that serves the React SPA and provides REST API
 * for audits, findings, history, config, and health checks.
 */

import express from 'express'
import cors from 'cors'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { readFileSync, existsSync, readdirSync, mkdirSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { spawn } from 'child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '../..')
const DATA_DIR = join(homedir(), '.spectra', 'data')
const HISTORY_FILE = join(DATA_DIR, 'history.json')

const app = express()
const PORT = parseInt(process.env.SPECTRA_WEB_PORT ?? '3456')

app.use(cors())
app.use(express.json())

// ─── Serve SPA ────────────────────────────────────────────────────────────────

const distDir = join(ROOT, 'dist/web')
if (existsSync(distDir)) {
  app.use(express.static(distDir))
} else {
  // Dev mode: serve from web/ dist
  const devDist = join(ROOT, 'web/dist')
  if (existsSync(devDist)) app.use(express.static(devDist))
}

app.get('*', (req, res) => {
  const spaPath = existsSync(distDir) ? join(distDir, 'index.html') : join(ROOT, 'web/dist/index.html')
  if (existsSync(spaPath)) res.sendFile(spaPath)
  else res.status(404).send('Web UI not built. Run: npm run web:build')
})

// ─── API Routes ───────────────────────────────────────────────────────────────

function ensureHistory(): any[] {
  if (!existsSync(HISTORY_FILE)) return []
  try { return JSON.parse(readFileSync(HISTORY_FILE, 'utf-8')) } catch { return [] }
}

function saveHistory(data: any[]): void {
  mkdirSync(DATA_DIR, { recursive: true })
  writeFileSync(HISTORY_FILE, JSON.stringify(data, null, 2), 'utf-8')
}

// GET /api/audits
app.get('/api/audits', (req, res) => {
  res.json(ensureHistory())
})

// GET /api/audits/:id
app.get('/api/audits/:id', (req, res) => {
  const audits = ensureHistory()
  const audit = audits.find((a) => a.investigation?.id === req.params.id || a.id === req.params.id)
  res.json(audit ?? null)
})

// DELETE /api/audits/:id
app.delete('/api/audits/:id', (req, res) => {
  let audits = ensureHistory()
  audits = audits.filter((a) => a.investigation?.id !== req.params.id && a.id !== req.params.id)
  saveHistory(audits)
  res.json({ ok: true })
})

// POST /api/audits (trigger new audit)
app.post('/api/audits', (req, res) => {
  const { target, depth = 'full', format = 'json', model = 'mock', dryRun = false } = req.body ?? {}
  if (!target) { res.status(400).json({ error: 'target is required' }); return }

  const auditId = `inv-${Date.now()}`
  res.json({ id: auditId, status: 'started', target })

  // Spawn Spectra CLI in background
  const cliBin = join(ROOT, 'dist/cli/index.js')
  const args = ['audit', target, '-q']
  if (depth === 'quick') args.push('-d', 'quick')
  if (format !== 'json') args.push('-f', format)
  if (model !== 'mock') args.push('-m', model)
  if (dryRun) args.push('--dry-run')

  const proc = spawn('node', [cliBin, ...args], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, SPECTRA_NO_TTY: '1' },
  })

  proc.on('close', (code) => {
    // Audit result will be picked up on next /api/audits call
    // The CLI writes to ~/.spectra/data/history.json
  })
})

// GET /api/findings
app.get('/api/findings', (req, res) => {
  const audits = ensureHistory()
  const severity = req.query.severity as string | undefined
  const limit = parseInt(req.query.limit as string ?? '50')
  
  const all: any[] = []
  for (const a of audits) {
    for (const f of a.investigation?.findings ?? []) {
      if (severity && f.severity !== severity) continue
      all.push({ ...f, auditTarget: a.target, auditDate: a.generatedAt })
    }
  }
  res.json(all.slice(0, limit))
})

// GET /api/history
app.get('/api/history', (req, res) => {
  const limit = parseInt(req.query.limit as string ?? '20')
  res.json(ensureHistory().slice(0, limit))
})

// GET /api/config
app.get('/api/config', (req, res) => {
  const cfgFile = join(homedir(), '.spectra', 'config.json')
  if (!existsSync(cfgFile)) {
    res.json({ defaultModel: 'mock', defaultFormat: 'json', autoApproveThreshold: 'medium', profiles: {}, apiKeys: {} })
    return
  }
  try { res.json(JSON.parse(readFileSync(cfgFile, 'utf-8'))) }
  catch { res.json({}) }
})

// PUT /api/config
app.put('/api/config', (req, res) => {
  const patch = req.body ?? {}
  const cfgFile = join(homedir(), '.spectra', 'config.json')
  let cfg: any = {}
  if (existsSync(cfgFile)) {
    try { cfg = JSON.parse(readFileSync(cfgFile, 'utf-8')) } catch { /* ignore */ }
  }
  Object.assign(cfg, patch)
  mkdirSync(join(homedir(), '.spectra'), { recursive: true })
  writeFileSync(cfgFile, JSON.stringify(cfg, null, 2))
  res.json({ ok: true, config: cfg })
})

// GET /api/health
app.get('/api/health', (req, res) => {
  const { spawnSync } = require('child_process')
  const home = homedir()
  const binCandidates = [join(home, '.npm-global', 'bin', 'spectra'), '/usr/local/bin/spectra', '/usr/bin/spectra']
  const bin = binCandidates.find((p: string) => existsSync(p)) ?? ''
  const dockerOk = spawnSync('docker', ['version'], { encoding: 'utf-8', timeout: 3000 }).status === 0
  
  res.json({
    nodeVersion: process.version.slice(1),
    npmVersion: spawnSync('npm', ['--version'], { encoding: 'utf-8' }).stdout.trim(),
    binPath: bin,
    version: '0.0.6',
    theme: process.env.SPECTRA_THEME ?? 'dark',
    configExists: existsSync(join(home, '.spectra', 'config.json')),
    dockerAvailable: dockerOk,
    issues: parseInt(process.version.slice(1)) < 20 && !bin ? ['Node.js < 20', 'Binary not found'] : [],
    warnings: !dockerOk ? ['Docker unavailable'] : [],
  })
})

// POST /api/benchmarks
app.post('/api/benchmarks', (res: any) => {
  // Stream benchmark results via SSE
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  
  const fixtureDir = join(ROOT, 'tests', 'fixtures')
  if (!existsSync(fixtureDir)) {
    res.write(`data: ${JSON.stringify({ event: 'error', message: 'No fixtures found\n' })}\n`)
    res.end()
    return
  }

  const fixtures = readdirSync(fixtureDir).filter((f: string) => existsSync(join(fixtureDir, f, 'README.md'))).sort()
  let idx = 0
  
  function next() {
    if (idx >= fixtures.length) {
      res.write(`data: ${JSON.stringify({ event: 'done' })}\n\n`)
      res.end()
      return
    }
    const fixture = fixtures[idx++]
    res.write(`data: ${JSON.stringify({ event: 'progress', fixture, status: 'running' })}\n\n`)
    setTimeout(next, 800)
  }
  next()
})

// ─── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  🔍 Hilbras Spectra Web UI`)
  console.log(`  ─────────────────────────────`)
  console.log(`  Frontend: http://localhost:3001`)
  console.log(`  Backend:  http://localhost:${PORT}`)
  console.log(`  Health:   http://localhost:${PORT}/api/health`)
  console.log(`─────────────────────────────\n`)
})
