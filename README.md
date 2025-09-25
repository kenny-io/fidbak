# Getting Started with the Fidbak Widget

Fidbak is a lightweight, framework‑free widget for collecting page‑level feedback (👍 / 👎 with optional comments). You can embed it on any site via ESM or a CDN script.

- Package: `@fidbak/widget`
- CDN (latest): `https://unpkg.com/@fidbak/widget@latest/dist/fidbak.fab.min.global.js`
- API Base (Production): `https://fidbak-api.primary-account-45e.workers.dev`

---

## Quick Start

### 0) Create your Site ID

Before you embed the widget, you need a Site ID. This tells Fidbak which site the feedback belongs to.

- Open the Fidbak Dashboard and create a new site. Copy the generated `siteId`.
- Alternatively (for developers), create a site via API:

```bash
curl -X POST "https://fidbak-api.primary-account-45e.workers.dev/v1/sites" \
  -H "content-type: application/json" \
  -d '{
    "id":"your-site-id",
    "name":"My Docs",
    "ownerEmail":"you@example.com",
    "origin":"https://your-domain.com",
    "origins":["http://localhost:5173"],
    "webhookUrl":"https://your-webhook-endpoint.com"
  }'
```

Once you have your `siteId`, use it in the widget config below.

### ESM (recommended)
```html
<script type="module">
  import fidbak from '@fidbak/widget';
  fidbak('init', {
    siteId: 'your-site-id', // paste the Site ID you created in step 0
    apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev',
    theme: 'auto',
    webhookUrl: 'https://your-webhook-endpoint.com'
  });
</script>
```

### CDN (no build tools)
```html
<script src="https://unpkg.com/@fidbak/widget@latest/dist/fidbak.fab.min.global.js"></script>
<script>
  window.fidbak('init', {
    siteId: 'your-site-id', // paste the Site ID you created in step 0
    apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev',
    theme: 'auto',
    webhookUrl: 'https://your-webhook-endpoint.com'
  });
</script>
```

The widget renders a floating action button (FAB). Clicking it opens a modal where users can rate the page and leave optional details.

---

## Configuration Options

Call `fidbak('init', options)` with the following fields.

### Required
- **siteId** (string)
  - Your unique site identifier. Create it via the dashboard or POST `/v1/sites`.

### Common
- **apiBaseUrl** (string)
  - Fidbak API base URL. If omitted, it defaults to `window.location.origin` (useful for same-origin deployments).

- **theme** (`'light' | 'dark' | 'auto'`, default `'auto'`)
  - Controls the widget theme. `'auto'` uses the user’s `prefers-color-scheme`.

- **position** (`'tl' | 'tr' | 'bl' | 'br'`, default `'br'`)
  - Docking corner for the FAB: top-left, top-right, bottom-left, bottom-right.

- **draggable** (boolean)
  - If enabled, allows the FAB to be dragged around the viewport (planned; reserved flag).

- **includeQuery** (boolean)
  - When true, the page identifier (`pageId`) includes the query string, otherwise only the pathname is used.

- **captureSelection** (boolean)
  - When true, the widget attempts to capture a small excerpt of selected text and the nearest heading for extra context.

- **debounceMs** (number, default `600000`)
  - Minimum interval (in ms) to suppress duplicate feedback from the same page/heading/user within a short time window.

- **debug** (boolean)
  - Enables verbose console logs. You can also set `localStorage['fidbak:debug']='1'`.

### Policy (advanced, optional)
`policy` is forwarded to the API to influence server-side handling (rate limits, CORS allowance, etc.).

- **policy.rateLimit**
  - `windowMs` (ms), `max` (count). Caps client submits per IP+siteId.
- **policy.corsAllow** (string[])
  - List of allowed origins for this request. The server merges this with its stored CORS config.
- **policy.ipAllow** (string[])
  - Strict IP allow list for this request.
- **policy.requireHmac** (boolean)
  - If true, the server requires a valid `x-fidbak-signature` for the request (see `signSecret`).

### Webhooks (optional)
- **webhookUrl** (string | string[])
  - One or more endpoints to receive webhook events in parallel.
- **webhookSecret** (string)
  - Secret used by the server to sign webhook bodies (as `x-fidbak-signature`).

### Client Signing (dev only)
- **signSecret** (string)
  - If provided, the widget computes an HMAC SHA-256 of the request body and sends it in `x-fidbak-signature`. Use only for development. For production, prefer server‑side signing.

### Theming (optional)
- **themeOverrides** (object)
  - Fine‑grained style overrides to match your brand. All fields are optional; omitted values fall back to sensible defaults.

```ts
interface ThemeOverrides {
  fontFamily?: string;
  radius?: { card?: number; input?: number; button?: number; thumb?: number; close?: number };
  colors?: {
    overlay?: string;
    cardBgLight?: string; cardBgDark?: string;
    textLight?: string; textDark?: string;
    borderLight?: string; borderDark?: string; focusRing?: string;
    // Primary pill (send)
    sendBtnBgLight?: string; sendBtnBgDark?: string;
    sendBtnBorderLight?: string; sendBtnBorderDark?: string;
    sendBtnTextLight?: string; sendBtnTextDark?: string;
    // Cancel pill
    cancelBtnBgLight?: string; cancelBtnBgDark?: string;
    cancelBtnBorderLight?: string; cancelBtnBorderDark?: string;
    cancelBtnTextLight?: string; cancelBtnTextDark?: string;
    // Thumb intent colors
    thumbUpBgLight?: string; thumbUpBgDark?: string; thumbUpBorder?: string;
    thumbDownBgLight?: string; thumbDownBgDark?: string; thumbDownBorder?: string;
    // FAB colors
    ghostBorderLight?: string; ghostBorderDark?: string;
    fabBgLight?: string; fabBgDark?: string; fabTextLight?: string; fabTextDark?: string;
  };
  spacing?: { cardPadding?: number };
  fab?: { size?: number };
}
```

---

## Page Context & What Gets Sent

When the user submits, the widget sends a structured payload:
```ts
{
  siteId: string,
  pageId: string,        // pathname or pathname+query depending on includeQuery
  rating: 'up' | 'down',
  comment?: string,
  email?: string,
  context: {
    title, url, referrer, scrollPct, nearestHeading, selectedText, ua, platform: 'web'
  },
  destinations?: string[],   // from webhookUrl
  webhookSecret?: string,
  policy?: PolicyOptions,
  themeOverrides?: ThemeOverrides
}
```

`pageId` ties feedback to the current page. Use the Dashboard to filter by site and page, or query the API directly.

---

## Programmatic Usage

- **Open the modal manually:**
  - (Planned) `fidbak('open')` will open the modal programmatically in a future version.
- **Re-render FAB:**
  - `fidbak('render')` will re-render the FAB using the current options.

---

## Tips

- Ensure your site origin is allowlisted on the API for your Site ID; otherwise browser calls may be blocked by CORS.
- For local testing with the API at a different origin, set `apiBaseUrl` accordingly.
- Use `debounceMs` to reduce duplicates during rapid interactions.
- Use `themeOverrides` to match your brand but keep good contrast for accessibility.

---

## How the Dashboard Manages Your Data (No Auth)

The current Fidbak Dashboard does not use authentication. To keep the experience simple during early access, it relies on:

- **Owner email** — When you create a site (via dashboard or API), you can set `ownerEmail`. The API supports listing sites by this email using `GET /v1/sites?ownerEmail=you@example.com`.
- **localStorage** — The dashboard stores your `ownerEmail` and the last viewed `siteId` in `localStorage` so it can automatically fetch and show your sites on return visits.

What this means for you:

- If you clear your browser storage or use a different browser/machine, the dashboard won’t remember your email. You’ll need to re-enter it or open a direct link with `?siteId=...`.
- The API email filter is a convenience, not security. Anyone who knows your email could query `GET /v1/sites?ownerEmail=<email>` if they can reach your API. CORS controls still apply to browser calls, but server‑side access is possible. Avoid exposing sensitive data via this endpoint.

Recommendations:

- Bookmark the dashboard URL with your `?siteId=...` once you create a site so you can quickly return to it.
- Keep your site IDs and dashboard links somewhere safe (e.g., your team docs or a password manager note).
- For production rollouts or multi‑user teams, we recommend adding proper auth (planned). Until then, treat the dashboard as a lightweight viewer.

> Note: Viewer access from browsers still depends on CORS allowlists per site. If your dashboard domain isn’t allowlisted for a site, the browser won’t be able to fetch its data from the API.

---

## Roadmap: Route-aware Display (planned)

We plan to support route-aware FAB visibility so you can show it only on certain sections (e.g., `/docs`). See `docs/widget-display-rules.md` for the proposal and examples.
