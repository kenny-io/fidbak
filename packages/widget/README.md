# fidbak (Widget)

Lightweight feedback FAB + modal. Framework‑free, zero dependencies.

## CDN usage (recommended)

```html
<script src="https://unpkg.com/fidbak@latest/dist/fidbak.min.js"></script>
<script>
  Fidbak.init({
    siteId: 'your-site-id',
    theme: 'auto',
    position: 'br'
  });
  // Later: Fidbak.render() (planned) to re-render programmatically
</script>
```

## ESM usage

```html
<script type="module">
  import Fidbak from 'fidbak';
  Fidbak.init({
    siteId: 'your-site-id',
    theme: 'auto',
    position: 'br'
    // Optional: apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev'
  });
</script>
```

## Options

- `siteId` string – your site identifier (create via dashboard).
- `apiBaseUrl` string – Fidbak API base URL (omit for production default; set when testing against custom envs).
- `theme` 'light' | 'dark' | 'auto' (default 'auto').
- `debounceMs` number (default 600000) – reduce duplicate sends.
- `debug` boolean – or set `localStorage['fidbak:debug']='1'`.

## Webhooks

Configure webhooks per site in the dashboard. We support Slack Incoming Webhooks and generic JSON endpoints. Generic endpoints receive `{ type: 'fidbak.feedback.v1', data: {...} }` and may include `x-fidbak-signature` (HMAC‑SHA256 of raw body) if you set a secret.

## License

MIT
