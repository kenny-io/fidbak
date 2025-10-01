# fidbak (Widget)

Lightweight, framework‑free, feedback Widget with zero dependencies. Collect feedback from your users from any site with ease.

# Usage
* Open the [Fidbak dashboard](https://fidbak.dev) and create a site. The dashboard will:
    * Return your `siteId`.
    * Let you add Allowed Origins (CORS).
    * Optionally add per‑site Webhooks (Slack or any URL).
    * Copy the generated code snippet and paste it before `</body>` of your site:

## CDN usage (recommended)

```html
<script src="https://unpkg.com/@fidbak/widget@latest/dist/fidbak.min.global.js"></script>
<script>
  // UMD global
  window.fidbak('init', {
    siteId: 'your-site-id',
    theme: 'auto',
    position: 'br'
  });
</script>
```

## ESM usage

```html
<script type="module">
  import fidbak from 'fidbak/widget';
  fidbak('init', {
    siteId: 'your-site-id',
    theme: 'auto',
    position: 'br'
  });
</script>
```

## Options

- `siteId` string – your site identifier (create via dashboard).
- `theme` 'light' | 'dark' | 'auto' (default 'auto').
- `debounceMs` number (default 600000) – reduce duplicate sends.

Find more options in the [Fidbak docs](https://github.com/kenny-io/fidbak?tab=readme-ov-file#configuration-options).

## Webhooks

Configure webhooks per site in the dashboard. We support Slack Incoming Webhooks and generic JSON endpoints. Generic endpoints receive 

```json 
{
  "type": "fidbak.feedback.v1",
  "data": {
    // feedback data
    }
}
```

The data may include `x-fidbak-signature` (HMAC‑SHA256 of raw body) if you set a webhook secret.

# How to use with Next.js

* Open the [Fidbak dashboard](https://fidbak.dev) and create a site to get your `siteId`. While creating the site, ensure `http://localhost:3000` or whichever port your Next.js app runs on is in Allowed Origins.
    
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

* Run your app and confirm the FAB shows. Submit a feedback and check your [Fidbak dashboard](https://fidbak.dev) for results and analytics.

## License

MIT
