# Getting Started with Fidbak

Fidbak is a lightweight widget and dashboard for collecting page‑level feedback (👍 / 👎 with optional comments). You embed a tiny script; submissions go to the Fidbak API; the dashboard visualizes analytics. Per‑site webhooks let you forward events to Slack or any custom endpoint.

- CDN (latest): `https://unpkg.com/fidbak@latest/dist/fidbak.min.js`
- API (production): `https://fidbak-api.primary-account-45e.workers.dev`

---

## Quick Start (Dashboard‑first)

1) Open the dashboard and create a site. The dashboard will:
- Return your `siteId`.
- Let you add Allowed Origins (CORS).
- Optionally add per‑site Webhooks (Slack or any URL).

2) Copy the generated snippet and paste it before `</body>` of your site:

### CDN (no build tools)
```html
<script src="https://unpkg.com/fidbak@latest/dist/fidbak.min.js"></script>
<script>
  Fidbak.init({
    siteId: 'your-site-id', // from dashboard
    // Optional: apiBaseUrl if different env, theme, etc.
    // apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev',
    // theme: 'auto'
  });
</script>
```

The widget renders a floating action button (FAB). Clicking it opens a modal where users can rate the page and leave optional details.

---

## Configuration Options

Call `Fidbak.init(options)` with the following fields.

### Required
- **siteId** (string)
  - Your unique site identifier. Create it via the dashboard or POST `/v1/sites`.

### Common
- **apiBaseUrl** (string)
  - Fidbak API base URL. Typically omit for production. If testing against another origin, set it explicitly.

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

### Webhooks (server‑managed)
- Add webhooks in the dashboard per site. We support Slack Incoming Webhooks and any generic JSON endpoint.
- Generic endpoints receive `{ type: 'fidbak.feedback.v1', data: {...} }` with optional `x-fidbak-signature: <hex>` (HMAC‑SHA256 of the raw body). Slack receives `{ text, blocks }`.

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


The dashboard uses Clerk JWTs for owner‑protected endpoints (e.g., listing/managing your sites, webhooks). Sites created previously may use `owner_email`; newer sites also store `owner_user_id` (Clerk `sub`). Ownership is validated by `sub` or email.

---

## Notes

- Ensure the page origin embedding the widget is in your site’s Allowed Origins.
- Align environments: the widget and dashboard should talk to the same API.

## Roadmap
- We plan to support route-aware FAB visibility so you can show it only on certain sections (e.g., `/docs`).
