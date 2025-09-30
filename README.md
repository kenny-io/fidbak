# Getting Started with Fidbak

Fidbak is a lightweight widget and dashboard for collecting page‑level feedback (👍 / 👎 with optional comments). You embed a tiny script; submissions go to the Fidbak API; the dashboard visualizes analytics. Per‑site webhooks let you forward events to Slack or any custom endpoint.

- CDN (latest): `https://unpkg.com/@fidbak/widget@latest/dist/fidbak.min.global.js`
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
<script src="https://unpkg.com/@fidbak/widget@latest/dist/fidbak.min.global.js"></script>
<script>
  window.fidbak('init', {
    siteId: 'your-site-id', // from dashboard
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
The widget auto-configures its API base URL; you don’t need to set `apiBaseUrl`.

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

## Tips

- Ensure your site origin is allowlisted on the API for your Site ID; otherwise browser calls may be blocked by CORS.
- For local testing against a different API origin, you can override `apiBaseUrl` in `Fidbak.init`, but it’s not required for normal usage.
- Use `debounceMs` to reduce duplicates during rapid interactions.
- Use `themeOverrides` to match your brand but keep good contrast for accessibility.

---


The dashboard uses Clerk JWTs for owner‑protected endpoints (e.g., listing/managing your sites, webhooks). Sites created previously may use `owner_email`; newer sites also store `owner_user_id` (Clerk `sub`). Ownership is validated by `sub` or email.

---

## Notes

- Ensure the page origin embedding the widget is in your site’s Allowed Origins.
- Align environments: the widget and dashboard should talk to the same API.

---

## Use in a Next.js App

* Open the [Fidbak dashboard](https://fidbak.dev/dashboard) and create a site to get your `siteId`. While creating the site, ensure `http://localhost:3000` or whichever port your Next.js app runs on is in Allowed Origins.
    
* Create a FidbakWidget component: 

```tsx
// app/components/FidbakWidget.tsx
"use client";
import { useEffect } from "react";
import { fidbak } from "@fidbak/widget";

export default function FidbakWidget() {
  useEffect(() => {
    fidbak("init", {
      siteId: "your-site-id", // real Site ID from your dashboard/API
      theme: "auto",
      position: "br",
    });
  }, []);
  return null;
}

```

Then and add it to your Next.js root layout file `app/layout.tsx`:

```tsx
import FidbakWidget from '@/components/FidbakWidget'
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <FidbakWidget />
        {children}
      </body>
    </html>
  )
}
```

* Run your app and confirm the FAB shows. Submit a feedback and check your [Fidbak dashboard](https://fidbak.dev/dashboard) for results and analytics.

### Test it
- Add your dev origin (e.g., `http://localhost:3000`) to Allowed Origins for the site in the Dashboard.
- Start Next.js and open the app; the FAB should appear bottom-right.
- Submit feedback and check Network → `/v1/feedback` → status 202.
- If webhooks are configured for the site, you’ll receive a Slack (or custom) notification.

## Roadmap
- We plan to support route-aware FAB visibility so you can show it only on certain sections (e.g., `/docs`).
