# Fidbak API Reference

Fidbak is a lightweight service for collecting user feedback (thumbs up/down with optional comments) from any website via a small embeddable widget. This document describes the HTTP API used by the Dashboard, Widget, and external integrations.

- Base URL (production): `https://fidbak-api.primary-account-45e.workers.dev`
- Content type: JSON request/response
- Auth: Public endpoints; browser access is governed by CORS allowlists per Site ID
- Errors: Non-2xx responses return JSON `{ ok: false, error: string }`
- Versioning: All endpoints are prefixed with `/v1`

> Tip for AI agents: unless otherwise specified, use standard JSON and include `content-type: application/json` for POST requests. Treat `siteId` as a required primary key for most dashboard queries.

---

## Conventions

- Timestamps are ISO-8601 strings (e.g. `2025-09-24T20:55:10.234Z`).
- Ratings are one of: `"up" | "down"`.
- Pagination uses `limit` and `offset` query parameters.
- For browser clients, requests must originate from a URL in the Site’s CORS allowlist.

---

## Health

GET `/v1/health`

- Purpose: Liveness probe and quick connectivity test.
- Response 200:
```json
{ "ok": true, "status": "healthy" }
```

### Site Stats (Dashboard analytics)

GET `/v1/sites/:id/stats?days=7`

- Purpose: Per-site analytics including lifetime totals, last N-day window, previous N-day window, and deltas for easy KPI cards.
- Path params:
  - `id` — Site ID
- Query params:
  - `days` — number (default 7, min 1, max 90)
- Response 200:
```json
{
  "totals": { "all": 120, "up": 98, "down": 22, "satisfactionPct": 81.67 },
  "lastN": { "days": 7, "up": 12, "down": 4, "total": 16, "satisfactionPct": 75 },
  "prevN": { "days": 7, "up": 8, "down": 8, "total": 16, "satisfactionPct": 50 },
  "deltas": { "totalPct": 0, "satisfactionPct": 25 }
}
```
- Notes:
  - `satisfactionPct` is computed as `up / (up + down) * 100`, rounded to 2 decimals.
  - `deltas.totalPct` compares lastN.total to prevN.total. If prev window is 0 and lastN has events, `totalPct` is reported as 100.

Example:
```bash
curl "$API/v1/sites/acme-docs/stats?days=7"
```

---

## Sites

### Create a Site

POST `/v1/sites`

- Purpose: Self-serve site creation. Registers a Site ID, allowlists origins for CORS, and returns a verification token (reserved for future verification flows).
- CORS: Open to any origin for onboarding, but the created site will only function from allowlisted origins.
- Request body:
```json
{
  "id": "string, lowercase-hyphens, min 3 characters",
  "name": "string (optional)",
  "ownerEmail": "string (optional email)",
  "origin": "string (required, must start with http:// or https://)",
  "origins": ["string", "string"]
}
```
- Notes:
  - `origins` (optional) is merged with `origin` and deduplicated.
- Responses:
  - 201 Created
```json
{
  "ok": true,
  "siteId": "acme-docs",
  "cors": ["https://docs.acme.com", "https://dashboard.example.com"],
  "verifyToken": "uuid-string",
  "dashboard": "https://your-dashboard.example.com/?siteId=acme-docs"
}
```
  - 400/422 on invalid input: `{ "ok": false, "error": "invalid_site_id" | "invalid_origin" }`
  - 500 on server error: `{ "ok": false, "error": "create_failed" }`

### List Sites (with optional owner filter)

GET `/v1/sites?ownerEmail=`

- Purpose: Return a list of sites with metadata and an aggregated feedback count.
- Query params:
  - `ownerEmail` — string (optional). When provided, returns only sites with `owner_email` equal to this value. If your deployment runs without D1 (memory fallback), the filter will return an empty list since ownership is not tracked in memory.
- Response 200:
```json
{
  "sites": [
    {
      "id": "acme-docs",
      "name": "Acme Docs",
      "owner_email": "owner@acme.com",
      "cors": ["https://docs.acme.com", "https://dashboard.example.com"],
      "created_at": "2025-09-24T20:55:10.234Z",
      "verified_at": null,
      "feedback_count": 42
    }
  ]
}
```

Example:
```bash
curl "$API/v1/sites?ownerEmail=owner@acme.com"
```

### Get Site Details

GET `/v1/sites/:id`

- Purpose: Retrieve site metadata and current CORS allowlist.
- Path params:
  - `id` — Site ID
- Response 200:
```json
{
  "id": "acme-docs",
  "name": "Acme Docs",
  "owner_email": "owner@acme.com",
  "cors": ["https://docs.acme.com", "https://dashboard.example.com"],
  "created_at": "2025-09-24T20:55:10.234Z",
  "verified_at": null
}
```
- 404: `{ "ok": false, "error": "not_found" }`

### Manage Site Origins (CORS)

POST `/v1/sites/:id/origins`

- Purpose: Add or remove CORS-allowed origins for a Site ID.
- Path params:
  - `id` — Site ID
- Request body:
```json
{
  "add": ["https://help.acme.com", "http://localhost:5173"],
  "remove": ["https://old.example.com"]
}
```
- Rules:
  - Only strings beginning with `http://` or `https://` are accepted.
  - Duplicates are ignored.
- Response 200:
```json
{ "ok": true, "siteId": "acme-docs", "cors": ["https://docs.acme.com", "http://localhost:5173"] }
```
- Errors:
  - 404: `{ "ok": false, "error": "not_found" }`
  - 400/422: `{ "ok": false, "error": "invalid_origin" }`
  - 500: `{ "ok": false, "error": "update_failed" }`

---

## Feedback

### Submit Feedback (Widget)

POST `/v1/feedback`

- Purpose: Called by the Fidbak widget to submit a rating and optional details.
- CORS: Must be called from an origin allowlisted for the target `siteId`.
- Request body:
```json
{
  "siteId": "acme-docs",
  "rating": "up",
  "comment": "Great docs!",
  "email": "me@example.com",
  "pageId": "/getting-started",
  "meta": { "userAgent": "...", "referrer": "..." }
}
```
- Response 200:
```json
{ "ok": true, "id": "fb_123", "created_at": "2025-09-24T20:55:10.234Z" }
```
- Errors:
  - 400 invalid input
  - 403 origin not allowed

### List Feedback (Dashboard)

GET `/v1/sites/:id/feedback?rating=&q=&limit=&offset=`

- Purpose: Paginated feedback listing for a Site ID.
- Path params:
  - `id` — Site ID
- Query params:
  - `rating` — `up | down` (optional)
  - `q` — search string (comment/page) (optional)
  - `limit` — number (e.g., 10, 20, 50; default 20)
  - `offset` — number (default 0)
- Response 200:
```json
{
  "items": [
    {
      "id": "fb_123",
      "site_id": "acme-docs",
      "page_id": "/getting-started",
      "rating": "up",
      "comment": "Great docs!",
      "email": "me@example.com",
      "created_at": "2025-09-24T20:55:10.234Z"
    }
  ],
  "total": 42,
  "nextOffset": 20
}
```
- Errors:
  - 404: `{ "ok": false, "error": "not_found" }`

### 7-Day Summary (Optional)

GET `/v1/sites/:id/summary?days=7`

- Purpose: Aggregate feedback summary used for dashboard charts.
- Path params:
  - `id` — Site ID
- Query params:
  - `days` — number (default 7)
- Example Response 200:
```json
{
  "days": 7,
  "series": [
    { "date": "2025-09-20", "up": 5, "down": 1 },
    { "date": "2025-09-21", "up": 2, "down": 0 }
  ],
  "totals": { "up": 25, "down": 4 }
}
```
- Notes: If not implemented on your API, clients should render a placeholder without throwing.

---

## CORS & Security

- CORS allowlisting per Site ID is the primary browser-side control. Only allowlisted origins can call feedback read/write endpoints successfully from the browser.
- Consider adding Turnstile/Recaptcha or rate limits on `POST /v1/sites` to reduce onboarding abuse.
- `verifyToken` is returned from `POST /v1/sites` and reserved for future verification flows (e.g., email verification) before enabling a site.

---

## Examples

Create a site:
```bash
API="https://fidbak-api.primary-account-45e.workers.dev"
curl -X POST "$API/v1/sites" \
  -H "content-type: application/json" \
  -d '{
    "id":"acme-docs",
    "name":"Acme Docs",
    "ownerEmail":"owner@acme.com",
    "origin":"https://docs.acme.com",
    "origins":["https://dashboard.example.com","http://localhost:5173"]
  }'
```

Get site details:
```bash
curl "$API/v1/sites/acme-docs"
```

Add localhost origins:
```bash
curl -X POST "$API/v1/sites/acme-docs/origins" \
  -H "content-type: application/json" \
  -d '{ "add": ["http://localhost:5173","http://localhost:5181"] }'
```

List feedback (first page):
```bash
curl "$API/v1/sites/acme-docs/feedback?limit=20&offset=0"
```

List feedback (thumbs up only, search):
```bash
curl "$API/v1/sites/acme-docs/feedback?rating=up&q=docs&limit=20&offset=0"
```

7-day summary:
```bash
curl "$API/v1/sites/acme-docs/summary?days=7"
```

List sites for an owner:
```bash
curl "$API/v1/sites?ownerEmail=owner@acme.com"
```

Site stats (KPIs for dashboard cards):
```bash
curl "$API/v1/sites/acme-docs/stats?days=7"
```

Submit feedback (widget):
```bash
curl -X POST "$API/v1/feedback" \
  -H "content-type: application/json" \
  -d '{
    "siteId":"acme-docs",
    "rating":"up",
    "comment":"Great docs!",
    "email":"me@example.com",
    "pageId":"/getting-started",
    "meta":{"userAgent":"Mozilla/...","referrer":"https://docs.acme.com"}
  }'
```

---

## Client Configuration (Dashboard)

- Browser clients should use `NEXT_PUBLIC_FIDBAK_API_BASE`.
- If the base URL is empty or not absolute, fall back to `window.location.origin` and construct URLs as `new URL(relativePath, base)`.

---

## Changelog

- 2025-09-25
  - Added list sites endpoint: `GET /v1/sites?ownerEmail=` (optional filter)
  - Added site analytics endpoint: `GET /v1/sites/:id/stats?days=`
- 2025-09-24
  - Added self-serve site creation: `POST /v1/sites`
  - Added origin management: `POST /v1/sites/:id/origins`
  - Added site details: `GET /v1/sites/:id`
  - Added feedback listing: `GET /v1/sites/:id/feedback`
  - Reserved summary endpoint: `GET /v1/sites/:id/summary`
