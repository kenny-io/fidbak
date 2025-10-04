# Fidbak API Reference

Fidbak is a lightweight service for collecting user feedback (thumbs up/down with optional comments) from any website via a small embeddable widget. This document describes the HTTP API used by the Dashboard, Widget, and external integrations.

- Base URL (production): `https://fidbak-api.primary-account-45e.workers.dev`
- Content type: JSON request/response
- Auth: Owner-protected endpoints require a Clerk JWT (Bearer). Public endpoints are governed by per-site CORS.
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
- Auth: Requires Bearer token (Clerk). The created site will only function from allowlisted origins.
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

### List Sites (owner)

GET `/v1/sites`

- Purpose: Return a list of sites for the authenticated owner with metadata and an aggregated feedback count.
- Auth: Requires Bearer token (Clerk). Ownership is checked via `owner_user_id` (sub) or `owner_email`.
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

### Get Site Details (owner)

GET `/v1/sites/:id`

- Purpose: Retrieve site metadata and current CORS allowlist.
- Auth: Requires Bearer token (Clerk) and owner must match.
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

### Manage Site Origins (CORS, owner)

POST `/v1/sites/:id/origins`

- Purpose: Add or remove CORS-allowed origins for a Site ID.
- Auth: Requires Bearer token (Clerk) and owner must match.
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
- Response 202 Accepted:
```json
{ "accepted": true, "id": "fb_123" }
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
- Preflight allows methods: GET, POST, PATCH, DELETE, OPTIONS. Allowed headers include `content-type`, `authorization`, and `x-fidbak-signature`.
- Consider adding Turnstile/Recaptcha or rate limits on `POST /v1/sites` to reduce onboarding abuse.
- `verifyToken` is returned from `POST /v1/sites` and reserved for future verification flows (e.g., email verification) before enabling a site.

---

## Webhooks (owner)

Fidbak supports per‑site webhooks. Configure them in the dashboard or via the endpoints below. We support Slack Incoming Webhooks and generic JSON endpoints.

### List Webhooks

GET `/v1/sites/:id/webhooks`

- Auth: Bearer token; owner must match.
- Response 200:
```json
{ "webhooks": [ { "id": "wh_1", "url": "https://...", "secret": null, "active": true, "created_at": "..." } ] }
```

### Create Webhook

POST `/v1/sites/:id/webhooks`

- Auth: Bearer token; owner must match.
- Request:
```json
{ "url": "https://your-endpoint.example.com/webhooks/fidbak", "secret": "optional", "active": true }
```
- Response 201:
```json
{ "ok": true, "webhook": { "id": "wh_1", "url": "https://...", "secret": null, "active": true, "created_at": "..." } }
```

### Update Webhook

POST `/v1/sites/:id/webhooks/:wid`

- Auth: Bearer token; owner must match.
- Request (any subset):
```json
{ "url": "https://new-url.example.com", "secret": "new-secret", "active": false }
```
- Response 200:
```json
{ "ok": true, "webhook": { "id": "wh_1", "url": "https://new-url.example.com", "secret": "new-secret", "active": false, "created_at": "..." } }
```

### Deactivate Webhook

POST `/v1/sites/:id/webhooks/:wid/delete`

- Auth: Bearer token; owner must match.
- Soft-deactivates the webhook (sets `active=false`).
- Response 200:
```json
{ "ok": true, "webhook": { "id": "wh_1" } }
```

### Delivery format

- Slack Incoming Webhooks (URLs under `https://hooks.slack.com/`):
  - Payload: `{ text, blocks }` (no signature header).
- Generic endpoints (any other HTTPS URL):
  - Payload: `{ "type": "fidbak.feedback.v1", "data": { /* feedback row */ } }`
  - If a secret is set on the webhook, Fidbak includes `x-fidbak-signature: <hex>` where `<hex>` is `HMAC_SHA256(secret, rawBody)`.
  - Verify by computing HMAC of the exact raw body string and comparing (case‑insensitive hex).

---

## Plans (public-ish)

GET `/v1/plans`

- Purpose: List available plans from the database (source of truth for the dashboard).
- Response 200:
```json
{ "plans": [ { "id": "pro", "name": "Pro", "monthly_event_limit": 10000, "price_id": "price_...", "features": {"sites": 3, "seats": 1} } ] }
```

---

## Billing (Stripe)

### Start Checkout (subscription)

POST `/v1/billing/checkout`

- Auth: Bearer token (Clerk)
- Body:
```json
{ "planId": "pro" }
```
- Response 200:
```json
{ "url": "https://checkout.stripe.com/..." }
```

### Customer Portal

GET `/v1/billing/portal`

- Auth: Bearer token (Clerk)
- Response 200: `{ "url": "https://billing.stripe.com/p/session/..." }`

### Webhook (Stripe)

POST `/v1/billing/webhook`

- Verifies Stripe signature using HMAC-SHA256.
- Handles subscription create/update/delete. Returns 200.

---

## Organization

### Get current org

GET `/v1/org`

- Auth: Bearer token (Clerk)
- Response 200:
```json
{
  "id": "org_123",
  "name": "Fidbak Team",
  "plan_id": "pro",
  "stripe_customer_id": null,
  "created_at": "2025-09-24T20:55:10.234Z",
  "price_id": null,
  "subscription_status": "active",
  "current_period_end": "2025-10-24T20:55:10.234Z",
  "cancel_at": null,
  "trial_end": null
}
```

### Update org name

PATCH `/v1/org`

- Auth: Bearer token (Clerk)
- Body:
```json
{ "name": "My Team" }
```
- Response 200: `{ "ok": true, "name": "My Team" }`

---

## Team Members (Org)

### List members

GET `/v1/org/members`

- Auth: Bearer token (Clerk)
- Response 200:
```json
{ "members": [ { "id": "m_1", "org_id": "org_123", "email": "a@b.com", "role": "admin", "status": "active", "invited_at": "...", "joined_at": "..." } ] }
```

### Invite member (email)

POST `/v1/org/members/invite`

- Auth: Bearer token (Clerk)
- Body:
```json
{ "email": "user@example.com", "role": "member" }
```
- Response 200:
```json
{ "ok": true, "accept_url": "https://dash.example.com/accept-invite?token=..." }
```
- Notes:
  - Generates a one-time invite token valid for ~7 days.
  - If email is configured (`RESEND_API_KEY` + `INVITE_FROM_EMAIL`), an invite email is sent.

### Pending invites (for signed-in user)

GET `/v1/org/members/pending`

- Auth: Bearer token (Clerk)
- Response 200:
```json
{ "invites": [ { "id": "m_2", "org_id": "org_123", "email": "me@example.com", "role": "member", "status": "pending", "invited_at": "...", "invite_token": "..." } ] }
```

### Accept invite by token (signed-in)

GET `/v1/org/members/accept?token=...`

- Auth: Bearer token (Clerk)
- Response 200: `{ "ok": true }`
- Errors: 400 `{ "ok": false, "error": "invalid_or_expired" }`

### Accept latest pending invite (in-app)

POST `/v1/org/members/accept`

- Auth: Bearer token (Clerk)
- Behavior: Finds the latest (most recent) non-expired pending invite for the user’s email and activates it.
- Response 200: `{ "ok": true }`
- Errors: 404 `{ "ok": false, "error": "no_pending" }`

### Remove member

POST `/v1/org/members/remove`

- Auth: Bearer token (Clerk)
- Body (one of): `{ "email": "user@example.com" }` or `{ "user_sub": "sub_123" }`
- Response 200: `{ "ok": true }`

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
