# Fidbak — Product Documentation

Fidbak is a lightweight, framework‑free user feedback widget (FAB + modal) with an edge API and a minimal dashboard. It lets you collect page‑aware feedback from any website and immediately fan it out to Slack or your own webhooks.

- Widget delivery: UMD (CDN drop) or ESM (`import fidbak from '@fidbak/widget'`)
- API: Cloudflare Workers + D1 (SQLite) with permissive dev defaults and production guardrails
- Dashboard: View, filter, and search feedback by site

---

## Components

- `packages/widget`
  - Heads‑up FAB and accessible modal. No framework required.
  - Ships UMD (global `window.fidbak`) and ESM.
- `apps/api`
  - Cloudflare Worker with endpoints to ingest feedback, persist to D1, and fanout to Slack / custom webhooks.
- `apps/dashboard`
  - Minimal viewer to browse stored items.

---

## Quickstart

1) Install dependencies (dev)

```bash
pnpm install
```

2) Start everything (dev)

```bash
pnpm dev
# API:        http://localhost:8787
# Docs (ESM): http://localhost:5173
# UMD:        http://localhost:5181
# Dashboard:  http://localhost:5174 (or 5173 if free)
```

3) (Optional) D1 database setup for persistence

```bash
npx wrangler login
npx wrangler d1 create fidbak           # copy database_id -> apps/api/wrangler.toml
npx wrangler d1 execute fidbak \
  --file apps/api/migrations/0001_init.sql
npx wrangler d1 execute fidbak \
  --command "INSERT INTO sites (id,name,hmac_secret,cors_json) VALUES ('demo-site','Demo Site', NULL, '[\"http://localhost:5173\",\"http://localhost:5174\",\"http://localhost:5181\"]');"
```

4) Test an example site

- ESM: open `http://localhost:5173` and click the FAB
- UMD: open `http://localhost:5181`
- Dashboard: set Site ID = `demo-site`, click Load

---

## Using the widget

### ESM

```html
<script type="module">
  import fidbak from '@fidbak/widget';
  fidbak('init', {
    siteId: 'YOUR_SITE_ID',
    apiBaseUrl: 'https://your-api.example.com',

    // Destinations (client-controlled)
    webhookUrl: ['https://hooks.slack.com/services/XXX/YYY/ZZZ'],
    webhookSecret: 'my-shared-secret',

    // Client-provided policy (server caps apply)
    policy: {
      corsAllow: ['https://your-site.example.com'],
      rateLimit: { windowMs: 60_000, max: 8 },
      requireHmac: false,
      slackChannel: '#feedback'
    },

    // UX & Theming
    theme: 'auto',                 // 'light' | 'dark' | 'auto'
    draggable: true,
    includeQuery: false,
    captureSelection: true,
    debounceMs: 0,                 // set >0 in prod (e.g., 30_000)

    // Brand styling (see full guide below)
    themeOverrides: {
      fontFamily: 'Inter, system-ui, sans-serif',
      radius: { card: 14, input: 10, button: 12, thumb: 12, close: 10 },
      colors: {
        // Send button pill (brandable per theme)
        sendBtnBgLight: '#e6fffb',
        sendBtnBorderLight: '#99f6e4',
        sendBtnTextLight: '#0f766e',
        sendBtnBgDark: '#042f2e',
        sendBtnBorderDark: '#2dd4bf',
        sendBtnTextDark: '#99f6e4',

        // Cancel button pill (brandable per theme)
        cancelBtnBgLight: '#fef2f2',
        cancelBtnBorderLight: '#fecdd3',
        cancelBtnTextLight: '#9f1239',
        cancelBtnBgDark: '#4c0519',
        cancelBtnBorderDark: '#fb7185',
        cancelBtnTextDark: '#fecdd3',

        // Optional focus and borders
        borderLight: '#e5e7eb',
        borderDark: '#374151',
        focusRing: 'rgba(59,130,246,0.35)'
      },
      spacing: { cardPadding: 16 },
      fab: { size: 56 }
    }
  });
</script>
```

### UMD

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

## Init Options

- **Core**
  - `siteId: string`
  - `theme?: 'light' | 'dark' | 'auto'`
  - `position?: 'tl' | 'tr' | 'bl' | 'br'`
  - `draggable?: boolean`
  - `includeQuery?: boolean`
  - `captureSelection?: boolean`
  - `apiBaseUrl?: string`
  - `debounceMs?: number` (default 10 minutes)

- **Fanout**
  - `webhookUrl?: string | string[]` — Slack or custom HTTPS endpoints
  - `webhookSecret?: string` — API will include `x-fidbak-signature` (HMAC SHA‑256)

- **Policy** (client-provided; server applies caps/safe defaults)
  - `policy.rateLimit?: { windowMs?: number; max?: number }`
  - `policy.corsAllow?: string[]`
  - `policy.ipAllow?: string[]`
  - `policy.requireHmac?: boolean`
  - `policy.slackChannel?: string`

- **Branding**
  - `themeOverrides?: {
      fontFamily?,
      radius?: { card?, input?, button?, thumb?, close? },
      colors?: {
        // Pills (preferred)
        sendBtnBgLight?, sendBtnBorderLight?, sendBtnTextLight?,
        sendBtnBgDark?,  sendBtnBorderDark?,  sendBtnTextDark?,
        cancelBtnBgLight?, cancelBtnBorderLight?, cancelBtnTextLight?,
        cancelBtnBgDark?,  cancelBtnBorderDark?,  cancelBtnTextDark?,
        // General
        overlay?, cardBgLight?, cardBgDark?, textLight?, textDark?,
        borderLight?, borderDark?, focusRing?,
        // Legacy gradient primary (still honored if provided)
        primaryStart?, primaryEnd?, primaryText?,
        // Optional FAB colors
        fabBgLight?, fabBgDark?, fabTextLight?, fabTextDark?
      },
      spacing?: { cardPadding? },
      fab?: { size? }
    }`

---

## Theming Guide

- **Defaults** are chosen for clarity, contrast, and a neutral look.
- **Pills (Send/Cancel)** are brandable with `sendBtn*` and `cancelBtn*` keys for both light and dark modes.
- **Thumbs**: selection state shows intent (👍 green tint, 👎 red tint) out of the box.
- **Typography**: set a custom `fontFamily` in `themeOverrides` and load the font in your page.

Example: Green brand on light, mint on dark

```js
themeOverrides: {
  colors: {
    sendBtnBgLight: '#ecfdf5', sendBtnBorderLight: '#86efac', sendBtnTextLight: '#065f46',
    sendBtnBgDark:  '#052e16', sendBtnBorderDark:  '#34d399', sendBtnTextDark:  '#86efac',
    cancelBtnBgLight:'#fef2f2', cancelBtnBorderLight:'#fecdd3', cancelBtnTextLight:'#9f1239',
    cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3'
  }
}
```

---

## API (Edge)

- `POST /v1/feedback` — accept feedback, store, and fanout
- `GET /v1/sites/:id/feedback` — list feedback (filters supported)

Bindings & Vars (Wrangler)

- `[[d1_databases]]` — `binding = "DB"`
- `[vars]` (optional)
  - `FIDBAK_SLACK_WEBHOOK` — server fallback Slack destination
  - `FIDBAK_HMAC_SECRET` — optional global HMAC secret (advanced)

Fanout

- Slack URLs get a Block Kit payload with rating, comment, page summary, and context.
- Non-Slack URLs get JSON: `{ type: 'fidbak.feedback.v1', data }` with `x-fidbak-signature` if `webhookSecret` was provided.

---

## Dashboard

- Start: `pnpm -C apps/dashboard dev`
- Enter `Site ID` (e.g., `demo-site`) and press Load.

---

## Security & Privacy

- **Client-controlled destinations**: convenient in dev; in prod, prefer server-stored destinations (coming soon) or set `FIDBAK_SLACK_WEBHOOK`.
- Enable reasonable rate limits and CORS allow‑lists via `policy`.
- Use `webhookSecret` for HMAC verification on your custom webhooks.

---

## Troubleshooting

- No Slack message?
  - Check API logs for `fidbak: slack response <status> <body>`.
  - Verify `webhookUrl` in init or set `FIDBAK_SLACK_WEBHOOK`.
- No POST in Network?
  - Ensure a thumb was selected, and consider `debounceMs: 0` for testing.
- ESM not picking changes?
  - Hard refresh; clear Vite prebundle cache.

---

## Roadmap

- Server‑stored destinations with dashboard settings
- Per‑site policy controls (server overrides)
- More theming hooks (thumb selected colors, presets)
- CI bundle size guardrails

---

## License

MIT
