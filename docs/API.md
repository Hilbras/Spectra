# API Reference

Base URL: `http://localhost:8080`

All endpoints return JSON. Errors follow the format:

```json
{
  "error": "description",
  "code": "ERROR_CODE"
}
```

## Health

### `GET /api/v1/health`

Health check endpoint.

**Response** `200 OK`:
```json
{
  "status": "healthy",
  "version": "0.1.1"
}
```

---

## Organizations

### `POST /api/v1/organizations`

Create a new organization.

**Request**:
```json
{
  "name": "Acme Corp",
  "slug": "acme-corp"
}
```

**Response** `201 Created`:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Corp",
  "slug": "acme-corp",
  "description": null
}
```

### `GET /api/v1/organizations`

List all organizations.

**Response** `200 OK`:
```json
[
  {
    "id": "...",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "description": null
  }
]
```

### `GET /api/v1/organizations/:id`

Get organization by ID.

**Response** `200 OK`: Organization object

**Errors**:
- `404 NOT_FOUND` — Organization not found

### `DELETE /api/v1/organizations/:id`

Delete an organization.

**Response** `204 No Content`

**Errors**:
- `404 NOT_FOUND` — Organization not found

---

## Projects

### `POST /api/v1/projects`

Create a new project.

**Request**:
```json
{
  "organization_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Web Application",
  "slug": "webapp"
}
```

**Response** `201 Created`:
```json
{
  "id": "...",
  "organization_id": "...",
  "name": "Web Application",
  "slug": "webapp",
  "description": null,
  "status": "active"
}
```

### `GET /api/v1/organizations/:org_id/projects`

List projects for an organization.

**Response** `200 OK`: Array of project objects

---

## Targets

### `POST /api/v1/targets`

Create a new target.

**Request**:
```json
{
  "project_id": "...",
  "name": "Production API",
  "target_type": "domain",
  "value": "api.example.com",
  "environment": "production"
}
```

**Target types**: `domain`, `url`, `ip`, `cidr`

**Environments**: `production`, `staging`, `development`, `testing`

**Response** `201 Created`:
```json
{
  "id": "...",
  "project_id": "...",
  "name": "Production API",
  "target_type": "domain",
  "value": "api.example.com",
  "environment": "production",
  "active": true
}
```

### `GET /api/v1/projects/:project_id/targets`

List targets for a project.

**Response** `200 OK`: Array of target objects

### `GET /api/v1/targets/:id`

Get target by ID.

**Response** `200 OK`: Target object

**Errors**:
- `404 NOT_FOUND` — Target not found

### `DELETE /api/v1/targets/:id`

Delete a target.

**Response** `204 No Content`

**Errors**:
- `404 NOT_FOUND` — Target not found

---

## Scans

### `POST /api/v1/scans`

Create and start a new scan.

**Request**:
```json
{
  "target_id": "..."
}
```

**Response** `201 Created`:
```json
{
  "scan_id": "...",
  "target_id": "...",
  "status": "started"
}
```

### `GET /api/v1/scans/:scan_id/observations`

List observations for a scan.

**Query parameters**:
- `type` (optional) — Filter by observation type

**Response** `200 OK`: Array of observation objects

---

## Findings

### `GET /api/v1/findings`

List all findings.

**Query parameters**:
- `severity` (optional) — Filter: `critical`, `high`, `medium`, `low`, `info`
- `status` (optional) — Filter: `new`, `confirmed`, `false_positive`, `investigating`, `fixed`, `accepted`, `duplicate`

**Response** `200 OK`: Array of finding objects

### `GET /api/v1/findings/:id`

Get finding by ID.

**Response** `200 OK`: Finding object

### `POST /api/v1/findings/:id/status`

Update finding status.

**Request**:
```json
{
  "status": "confirmed"
}
```

**Valid statuses**: `new`, `confirmed`, `false_positive`, `investigating`, `fixed`, `accepted`, `duplicate`

**Response** `200 OK`: Updated finding object

---

## Evidence

### `GET /api/v1/findings/:finding_id/evidence`

List evidence for a finding.

**Response** `200 OK`: Array of evidence objects

---

## Verification

### `GET /api/v1/findings/:finding_id/verification`

List verification records for a finding.

**Response** `200 OK`: Array of verification objects

### `GET /api/v1/verification/summary`

Get verification summary statistics.

**Response** `200 OK`:
```json
{
  "total": 42,
  "verified": 30,
  "unverified": 10,
  "false_positive": 2,
  "average_confidence": 0.85
}
```

---

## Statistics

### `GET /api/v1/stats`

Get platform statistics.

**Response** `200 OK`:
```json
{
  "total_findings": 42,
  "findings_by_severity": {
    "critical": 5,
    "high": 12,
    "medium": 15,
    "low": 8,
    "info": 2
  },
  "findings_by_status": {
    "new": 20,
    "confirmed": 15,
    "investigating": 5,
    "false_positive": 2
  }
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid input |
| `SCOPE_VIOLATION` | 403 | Target out of scope |
| `CONFLICT` | 409 | Resource already exists |
| `INTERNAL_ERROR` | 500 | Server error |
| `INVALID_UUID` | 400 | Malformed UUID |

## Authentication

v0.1.1 does not include built-in authentication. Use network-level security (firewall, VPN, reverse proxy with auth) to protect the API.

Future versions will support API key and OAuth2 authentication.
