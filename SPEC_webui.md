# Hilbras Spectra — Web UI Specification

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Browser                           │
│  ┌────────────────────────────────────────────────┐  │
│  │           React + Vite SPA                     │  │
│  │  (Source: web/src/)                            │  │
│  └────────────────────┬───────────────────────────┘  │
│                       │ REST + SSE                   │
├───────────────────────┼──────────────────────────────┤
│              Express API Server                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  GET  /api/audits        List all audits        │  │
│  │  GET  /api/audits/:id    Get audit details      │  │
│  │  POST /api/audits        Trigger audit          │  │
│  │  GET  /api/findings      Browse findings        │  │
│  │  GET  /api/history       Audit history          │  │
│  │  GET  /api/config        Current config         │  │
│  │  PUT  /api/config        Update config          │  │
│  │  GET  /api/health        System health          │  │
│  │  WS   /ws/audit/:id    Live progress stream   │  │
│  └────────────────────┬───────────────────────────┘  │
│                       │                              │
│  ┌────────────────────▼───────────────────────────┐  │
│  │        Spectra Core Library                     │  │
│  │  (investigation/runtime/controller)             │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Features

### Pages
1. **Dashboard** — Overview with score gauges, recent audits, quick actions
2. **Audit** — Run new audit with target selection, options, live progress
3. **Findings** — Table browser with severity filters, sort, detail panel
4. **History** — Timeline of all past audits with comparison
5. **Projects** — Manage project profiles
6. **Settings** — Config editor, theme switcher, API key management

### Components
- `ScoreGauge` — Circular SVG progress indicator
- `FindingCard` — Individual finding with severity badge
- `AuditTimeline` — Phase progress visualization
- `ProjectCard` — Quick-launch audit card
- `ThemeToggle` — Dark/light switch
- `LiveProgress` — Real-time phase updates via SSE

### Data Model
- All data stored in `~/.spectra/data/` (shared with CLI)
- Audits saved as JSON, loaded on demand
- No external database required (JSON files = persistence)

## Files to Create

```
web/                          # Frontend
  package.json                # Vite + React deps
  vite.config.ts
  tsconfig.json
  index.html
  src/
    main.tsx                  # Entry point
    App.tsx                   # Router + layout
    components/
      Layout.tsx              # Shell with nav + theme
      ScoreGauge.tsx          # Circular score display
      FindingCard.tsx         # Single finding
      AuditTimeline.tsx       # Phase progress bar
      ProjectCard.tsx         # Project quick action
      ThemeToggle.tsx         # Theme switcher
      LiveProgress.tsx        # SSE-driven progress
    pages/
      Dashboard.tsx
      Audit.tsx
      Findings.tsx
      History.tsx
      Projects.tsx
      Settings.tsx
    hooks/
      useApi.ts               # Fetch wrapper
      useSse.ts               # Server-sent events
      useTheme.ts             # Theme context
    themes/
      dark.ts                 # Dark theme tokens
      light.ts                # Light theme tokens
    types/                    # Shared TS types
    App.css                   # Global styles

src/web/                      # Backend
  server.ts                   # Express server setup
  routes/
    audits.ts                 # Audit CRUD + trigger
    findings.ts               # Findings browser
    history.ts                # History queries
    config.ts                 # Config get/set
    health.ts                 # Health endpoint
  middleware/
    cors.ts                   # CORS for dev
  api-client.ts               # Lightweight HTTP client (for embedding)

package.json additions:
  "scripts": {
    "web:dev": "vite --port 3001",
    "web:build": "vite build",
    "web:start": "node dist/web/server.js",
    "dev": "concurrently \"npm run web:dev\" \"tsx watch src/web/server.ts\""
  },
  "dependencies": {
    "express": "^4.21.0",
    "cors": "^2.8.5",
    "sse-channel": "^4.0.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.0",
    "typescript": "^5.6.0"  (upgrade from ^7)
  }
```
