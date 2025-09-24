# @fidbak/widget

Lightweight feedback FAB + modal. Framework‑free, zero dependencies.

• ESM for npm import
• UMD for CDN `<script>`

## Install

```bash
npm i @fidbak/widget
# or
pnpm add @fidbak/widget
```

## Usage (ESM)

```html
<script type="module">
  import fidbak from '@fidbak/widget';
  fidbak('init', {
    siteId: 'demo-site',
    apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev',
    theme: 'auto',
  });
  // Later: window.fidbak('open') to open programmatically
</script>
```

## Usage (CDN)

```html
<script src="https://unpkg.com/@fidbak/widget@0.1.2/dist/fidbak.fab.min.global.js"></script>
<script>
  window.fidbak('init', {
    siteId: 'demo-site',
    apiBaseUrl: 'https://fidbak-api.primary-account-45e.workers.dev',
    theme: 'auto'
  });
</script>
```

## Options (common)

- `siteId` string – your site identifier.
- `apiBaseUrl` string – Fidbak API base URL.
- `theme` 'light' | 'dark' | 'auto' (default 'auto').
- `debounceMs` number (optional, default 600000) – reduce duplicate sends.
- `debug` boolean (optional) – or set `localStorage['fidbak:debug']='1'`.

## License

MIT
