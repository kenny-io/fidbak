# Contributions Guide

Thank you for your interest in contributing to Fidbak! This document explains how to set up the project locally, coding guidelines, and how to submit changes.

Fidbak consists of:
- `apps/api/` — Cloudflare Workers API (D1 database, JWT auth via Clerk, per-site webhooks)
- `packages/widget/` — The embeddable feedback widget (vanilla TS, ESM and UMD bundles)
- `examples/` — Example usage and docs snippets

A separate dashboard app lives in a sibling repo: `fidbak-dash/`.

---

## Prerequisites
- Node.js ≥ 18 (project currently tested on Node 22.x)
- npm (or pnpm/yarn) — examples use `npm`
- Wrangler CLI for Cloudflare Workers
  - Recommended: `npm i -D wrangler@4`
- A Cloudflare account with D1 enabled (for API development)
- A Clerk project (for authenticated, owner-only endpoints)

Optional (for local verification):
- `jq` and `curl` for API testing

---

## Repository Structure
```
apps/
  api/                 # Cloudflare Worker API (TypeScript)
examples/
  cdn-umd/
  docs-site/
packages/
  widget/              # Embeddable widget (TypeScript)
```

---

## Getting Started

1) Clone the repo and install dependencies:
```bash
npm install
```

2) Build the widget (optional during active dev if your editor compiles on save):
```bash
npm run build --workspace packages/widget
```

3) Configure API environment (`apps/api/wrangler.toml`):
- Set your D1 binding and environment vars for Clerk and dashboard origin, e.g.
```toml
[env.local]
name = "fidbak-api-local"

[env.local.vars]
CLERK_ISSUER = "https://<your-dev-subdomain>.clerk.accounts.dev"
CLERK_JWKS_URL = "https://<your-dev-subdomain>.clerk.accounts.dev/.well-known/jwks.json"
FIDBAK_DASH_ORIGIN = "http://localhost:8080"
FIDBAK_DASHBOARD_BASE = "http://localhost:8080"

# Optional secondary issuer support, if your dashboard uses a different issuer
CLERK_ISSUER_2 = "https://..."
CLERK_JWKS_URL_2 = "https://.../.well-known/jwks.json"
```

4) Deploy or run the API:
```bash
# Deploy to a Cloudflare environment (preferred for D1-backed dev)
cd apps/api
npx wrangler deploy --env local

# Tail logs
npx wrangler tail --env local --format=pretty
```

5) Test the API quickly:
```bash
curl -s "https://fidbak-api-local.<your-account>.workers.dev/v1/health"
```

6) Use examples to try the widget (e.g., `examples/docs-site/`). Ensure the site origin is allow‑listed in the API via the dashboard or `/v1/sites` endpoints.

---

## API Notes (apps/api)
- Auth: Owner-only endpoints require a valid Clerk JWT (Bearer). The API prefers `owner_user_id` (Clerk `sub`) and falls back to `owner_email` when present.
- Webhooks: Per-site webhooks stored in D1. Deliveries are logged (with redaction for Slack URLs).
- CORS: Preflight is cached with `Access-Control-Max-Age` to reduce OPTIONS latency.
- Deletion: Sites can be deleted via `POST /v1/sites/:id/delete` or `DELETE /v1/sites/:id` (owner-only). Deletion removes feedback and site webhooks.

---

## Widget Notes (packages/widget)
- Default API base points to production; consumers typically don’t need to set `apiBaseUrl`.
- `debounceMs` defaults to `0` (disabled). If set > 0, successful submissions will debounce subsequent attempts for the duration.
- Errors on non-2xx responses are surfaced to prevent false “success” UX.

---

## Coding Guidelines
- TypeScript for both API and widget.
- Prefer small, focused PRs. Include context in the PR description.
- Keep imports at the top of files.
- Add inline comments/logs when changing auth/webhook flows; redact secrets in logs.
- Ensure any new API endpoints include proper CORS and auth semantics.

Formatting & linting:
- Follow project’s existing formatting. If adding tooling:
  - Prettier for formatting, ESLint for linting. Keep config minimal.

Commits & branches:
- Use descriptive commit messages. Conventional Commits are welcome but not required (e.g., `feat(api): add DELETE /v1/sites/:id`).
- Branch naming suggestion: `feat/...`, `fix/...`, `chore/...`.

---

## Testing
- Add small integration tests where feasible (e.g., API route handlers using Miniflare/Workerd). If unavailable, provide a `curl` reproducer in the PR.
- For widget changes, test via examples and verify network calls and error handling in the browser.

---

## Security & Secrets
- Do not commit secrets. Use Wrangler `vars`/`secret` or environment-specific `wrangler.toml` sections.
- Never log raw secrets. The API redacts Slack webhook URLs in logs by default.

---

## Submitting a PR
1) Fork and create a feature branch.
2) Make your changes with clear, incremental commits.
3) Add or update documentation (README, examples, or inline comments) where relevant.
4) Verify API routes (auth, CORS) and widget behavior locally.
5) Open a PR with:
   - Description, motivation, and testing notes (including curl samples where helpful)
   - Screenshots/GIFs for UI-affecting changes (if applicable)

We review PRs for correctness, clarity, and maintainability. Thank you for helping improve Fidbak! 🚀
