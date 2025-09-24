# Fidbak

Framework‑free feedback widget (FAB + modal) that works on any site via CDN or npm. Includes a Cloudflare Workers API with D1 storage and a lightweight dashboard.

## Getting Started

Follow these steps to see Fidbak working end‑to‑end locally in a few minutes.

1) Install dependencies

```bash
pnpm install
```

2) Start everything (API on :8787; Vite apps on :5173/5174 and :5181)

```bash
pnpm dev
# API will bind to http://localhost:8787
# ESM docs site on http://localhost:5173
# UMD example on http://localhost:5181
# Dashboard on http://localhost:5173 
```

3) Create a local D1 DB and apply migrations (one‑time) and seed it

```bash
npx wrangler login                        # one-time auth
npx wrangler d1 create fidbak             # copy database_id into apps/api/wrangler.toml
npx wrangler d1 execute fidbak \
  --file apps/api/migrations/0001_init.sql
npx wrangler d1 execute fidbak \
  --command "INSERT INTO sites (id,name,hmac_secret,cors_json) VALUES ('demo-site','Demo Site', NULL, '[\"http://localhost:5173\",\"http://localhost:5174\",\"http://localhost:5181\"]');"
```

4) Choose an integration

* ESM (docs, frameworks): open examples/docs-site/*.html and ensure the page contains:

```bash
<script type="module">
  import fidbak from '@fidbak/widget';
  fidbak('init', {
    siteId: 'demo-site',
    apiBaseUrl: 'http://localhost:8787',
    webhookUrl: ['https://hooks.slack.com/services/XXX/YYY/ZZZ'],
    policy: {
      corsAllow: ['http://localhost:5173','http://localhost:5174','http://localhost:5181']
    },
    debounceMs: 0
  });
</script>
```
* UMD (CDN style): open 
examples/cdn-umd/index.html and ensure this exists:

```bash
<script src="/@fs/Users/you/path/fidbak/packages/widget/dist/fidbak.fab.min.global.js"></script>
<script>
  window.fidbak('init', {
    siteId: 'demo-site',
    apiBaseUrl: 'http://localhost:8787',
    webhookUrl: ['https://hooks.slack.com/services/XXX/YYY/ZZZ'],
    debounceMs: 0
  });
</script>
```

5) Test
* Open http://localhost:5173 (ESM) or http://localhost:5181 (UMD), click the FAB, choose 👍/👎, write a comment, Send.
* Open the API terminal; you should see:
POST /v1/feedback 202 Accepted
fidbak: posting to Slack ...
fidbak: slack response 200 ok
* Open the Dashboard (http://localhost:5174), set demo-site, click Load to view items.

6) Production checklist
* Host the API (Cloudflare Worker) and bind a D1 database.
* Prefer server‑stored destinations (coming soon) or set a server default FIDBAK_SLACK_WEBHOOK.
* Keep policy conservative (CORS allow‑list + sensible rate limits).
* Use themeOverrides to match your brand.


## Highlights

- **Widget everywhere**
  - UMD (CDN drop) or ESM (`import fidbak from '@fidbak/widget'`).
  - No framework required; tiny, accessible modal.
- **Plug‑and‑play fanout**
  - Client can supply `webhookUrl` destinations (Slack detected automatically).
  - Server can also set a default fallback (e.g. `FIDBAK_SLACK_WEBHOOK`).
  - Optional HMAC signing for generic JSON webhooks.
- **Policy from the client**
  - CORS allow‑list, IP allow‑list, rate‑limit window/max, `requireHmac`.
  - Server caps and safe defaults applied.
- **Brandable UI**
  - `themeOverrides` to customize font, radii, colors, button gradients, FAB size.
- **Persistence**
  - D1 backed (with in‑memory fallback for dev without DB), plus a minimal dashboard.

---

## Monorepo layout

- `packages/widget` — Heads‑up FAB + modal. UMD + ESM.
- `apps/api` — Cloudflare Worker API with D1.
- `apps/dashboard` — Minimal admin dashboard.
- `examples/docs-site` — ESM example site.
- `examples/cdn-umd` — CDN/UMD example site.

---

## Quickstart (local dev)

Prereqs: pnpm, Node 18+.

1) Install deps

```bash
pnpm install
```

2) Start everything (API on :8787; Vite apps on :5173/5174 and :5181)

```bash
pnpm dev
```

3) Open examples

- ESM docs site: http://localhost:5173
- UMD example:   http://localhost:5181
- Dashboard:     http://localhost:5174 (or 5173 if free)

4) Submit feedback from either example then click “Load” in the dashboard for the site id (default `demo-site`).

---

## Using the widget

### ESM (recommended)

```html
<script type="module">
  import fidbak from '@fidbak/widget';

  fidbak('init', {
    siteId: 'YOUR_SITE_ID',
    apiBaseUrl: 'https://your-api.example.com',

    // 1) Fanout destinations (client-controlled)
    webhookUrl: [
      'https://hooks.slack.com/services/XXX/YYY/ZZZ',
      'https://your-service.example.com/fidbak'
    ],
    // Optional: API will HMAC sign the generic JSON webhook body
    webhookSecret: 'my-shared-secret',

    // 2) Behavior & safety (client-provided)
    policy: {
      corsAllow: ['https://your-site.example.com'],
      rateLimit: { windowMs: 60000, max: 8 },
      ipAllow: [],
      requireHmac: false,
      slackChannel: '#docs-feedback' // optional channel override
    },

    // 3) UI customization (brand theming)
    theme: 'auto', // 'light' | 'dark' | 'auto'
    themeOverrides: {
      fontFamily: 'Inter, system-ui, sans-serif',
      radius: { card: 14, input: 10, button: 12, thumb: 12, close: 10 },
      colors: {
        primaryStart: '#6366f1', 
        primaryEnd:   '#4f46e5', 
        primaryText:  '#fff',
        borderLight:  '#e5e7eb',
        borderDark:   '#374151',
        fabBgLight:   '#111',
        fabBgDark:    '#111',
        fabTextLight: '#fff',
        fabTextDark:  '#fff',
        focusRing: 'rgba(99,102,241,0.35)'
      },
      spacing: { cardPadding: 16 },
      fab: { size: 56 }
    },

    // 4) UX
    position: 'br',
    draggable: true,
    includeQuery: false,
    captureSelection: true,
    debounceMs: 0 // 0 for testing; raise in prod (e.g., 30_000)
  });
</script>
```

### UMD (CDN drop)

```html
<script src="/path/to/fidbak.fab.min.global.js"></script>
<script>
  window.fidbak('init', {
    siteId: 'YOUR_SITE_ID',
    apiBaseUrl: 'https://your-api.example.com',
    webhookUrl: 'https://hooks.slack.com/services/XXX/YYY/ZZZ',
    debounceMs: 0
  });
</script>
```

---

## Init options (reference)

- **Core**
  - `siteId: string`
  - `theme?: 'light' | 'dark' | 'auto'`
  - `position?: 'tl' | 'tr' | 'bl' | 'br'`
  - `draggable?: boolean`
  - `includeQuery?: boolean`
  - `captureSelection?: boolean`
  - `apiBaseUrl?: string`
  - `debounceMs?: number` (default 10 mins; set small/0 for testing)

- **Fanout**
  - `webhookUrl?: string | string[]` — client-supplied destinations.
  - `webhookSecret?: string` — API signs generic JSON webhook body with HMAC SHA‑256.

- **Policy** (client-provided, server applies caps/safe defaults)
  - `policy.rateLimit?: { windowMs?: number; max?: number }`
  - `policy.corsAllow?: string[]`
  - `policy.ipAllow?: string[]`
  - `policy.requireHmac?: boolean`
  - `policy.slackChannel?: string` — optional channel override.

- **Branding**
  - `themeOverrides?: {`
    - `fontFamily?: string`
    - `radius?: { card?, input?, button?, thumb?, close? }`
    - `colors?: { overlay?, cardBgLight?, cardBgDark?, textLight?, textDark?, borderLight?, borderDark?, focusRing?, primaryStart?, primaryEnd?, primaryText?, ghostBorderLight?, ghostBorderDark?, fabBgLight?, fabBgDark?, fabTextLight?, fabTextDark? }`
    - `spacing?: { cardPadding? }`
    - `fab?: { size? }`
  `}`

---

## API (Cloudflare Workers + D1)

### Local dev

1) Login to Cloudflare (one-time):

```bash
npx wrangler login
```

2) Create D1 DB (one-time) and bind in `apps/api/wrangler.toml`:

```bash
npx wrangler d1 create fidbak
# copy database_id into [[d1_databases]] in wrangler.toml
```

3) Apply migrations and seed demo site:

```bash
npx wrangler d1 execute fidbak --file apps/api/migrations/0001_init.sql
npx wrangler d1 execute fidbak --command "INSERT INTO sites (id,name,hmac_secret,cors_json) VALUES ('demo-site','Demo Site', NULL, '[\"http://localhost:5173\",\"http://localhost:5174\",\"http://localhost:5181\"]');"
```

4) Run the API:

```bash
pnpm -C apps/api dev
# We pin dev to http://localhost:8787
```

### Environment variables (optional)

- `FIDBAK_SLACK_WEBHOOK` — server default Slack destination (used if client didn’t send `webhookUrl`).
- `FIDBAK_HMAC_SECRET` — require/verify HMAC on client->API (if you enable `policy.requireHmac` you must also set a site secret in DB).

### Endpoints (preview)

- `POST /v1/feedback` — accepts widget payload; stores into D1; fans out to destinations.
- `GET /v1/sites/:id/feedback?limit=&offset=&rating=&q=` — lists feedback for dashboard.

---

## Dashboard

- Dev: `pnpm -C apps/dashboard dev` then open the printed Vite URL.
- Enter a `Site ID` (e.g., `demo-site`) and click Load.

---

## Security and production notes

- **Client-provided destinations** are convenient but can be modified by any script on the page.
  - Use CORS allow-list + rate limiting (supported by `policy`).
  - Prefer server-stored destinations for multi-team/prod setups (see "Next").
  - Use `webhookSecret` so your custom webhooks can verify the HMAC header.
- **Fanout**
  - Slack URLs get Block Kit payloads.
  - Non-Slack URLs get JSON `{ type: 'fidbak.feedback.v1', data }` with `x-fidbak-signature` if `webhookSecret` provided.

---

## Troubleshooting

- No Slack messages? Check API logs. You should see:
  - `fidbak: posting to Slack ...`
  - `fidbak: slack response <status> <body>`
- ESM example not posting?
  - Ensure `webhookUrl` is present in the init config on that page, or set `FIDBAK_SLACK_WEBHOOK` as a server fallback.
  - For local dev, clear Vite prebundle cache if a workspace dependency changed.
- Not seeing POSTs?
  - `debounceMs` may drop duplicates. Set `debounceMs: 0` while testing.

---

## Roadmap / Next

- D1-backed per-site destinations table + dashboard settings screen.
- Optional per-site server policies that can override client-provided ones.
- Bundle size guardrails in CI and visual polish iterations.

---

## Scripts

```bash
pnpm dev        # run api + dashboard + widget watch + examples
pnpm build      # build all packages
pnpm test       # run tests
```

---

## License

MIT

---

## Brand Presets (copy‑paste)

You can override any color set via `themeOverrides.colors`. Below are sample palettes.

### Emerald (default look)

```js
themeOverrides: {
  colors: {
    sendBtnBgLight: '#ecfdf5', sendBtnBorderLight: '#86efac', sendBtnTextLight: '#065f46',
    sendBtnBgDark:  '#052e16', sendBtnBorderDark:  '#34d399', sendBtnTextDark:  '#86efac',
    cancelBtnBgLight:'#fef2f2', cancelBtnBorderLight:'#fecdd3', cancelBtnTextLight:'#9f1239',
    cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
    thumbUpBgLight: '#ecfdf5', thumbUpBgDark: '#052e16', thumbUpBorder: '#34d399',
    thumbDownBgLight: '#fef2f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#f87171'
  }
}
```

### Indigo

```js
themeOverrides: {
  colors: {
    sendBtnBgLight: '#eef2ff', sendBtnBorderLight: '#c7d2fe', sendBtnTextLight: '#3730a3',
    sendBtnBgDark:  '#1e1b4b', sendBtnBorderDark:  '#a78bfa', sendBtnTextDark:  '#c7d2fe',
    cancelBtnBgLight:'#fef2f2', cancelBtnBorderLight:'#fecdd3', cancelBtnTextLight:'#9f1239',
    cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
    thumbUpBgLight: '#eef2ff', thumbUpBgDark: '#1e1b4b', thumbUpBorder: '#818cf8',
    thumbDownBgLight: '#fef2f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185'
  }
}
```

### Slate

```js
themeOverrides: {
  colors: {
    sendBtnBgLight: '#f1f5f9', sendBtnBorderLight: '#cbd5e1', sendBtnTextLight: '#0f172a',
    sendBtnBgDark:  '#0b1220', sendBtnBorderDark:  '#64748b', sendBtnTextDark:  '#cbd5e1',
    cancelBtnBgLight:'#fff1f2', cancelBtnBorderLight:'#fecdd3', cancelBtnTextLight:'#9f1239',
    cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
    thumbUpBgLight: '#e2e8f0', thumbUpBgDark: '#0b1220', thumbUpBorder: '#94a3b8',
    thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185'
  }
}
```
