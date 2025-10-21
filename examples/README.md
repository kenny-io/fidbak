# Fidbak Examples

These examples demonstrate the Fidbak widget integration with the new `alwaysShowComment` feature.

## Examples Overview

### 1. **docs-site** (ESM/Module Example)
A multi-page static documentation site using ESM imports.
- **Port**: 5180
- **Features**: Text/Icon FAB variants, theme customization, alwaysShowComment toggle
- **Integration**: Uses `import fidbak from '@fidbak/widget'`

### 2. **cdn-umd** (CDN/Global Example)
A single-page example loading the widget via CDN (UMD bundle).
- **Port**: 5181
- **Features**: Text/Icon FAB variants, palette selector, alwaysShowComment toggle
- **Integration**: Uses global `window.fidbak()`

---

## How to Run

### Prerequisites
Make sure the widget is built first:
```bash
cd /Users/ekene/CascadeProjects/fidbak/packages/widget
pnpm build
```

### Running docs-site (ESM Example)

**Terminal 1:**
```bash
cd /Users/ekene/CascadeProjects/fidbak/examples/docs-site
pnpm install
pnpm dev
```

Then open: **http://localhost:5180**

### Running cdn-umd (CDN Example)

**Terminal 2:**
```bash
cd /Users/ekene/CascadeProjects/fidbak/examples/cdn-umd
pnpm install
pnpm dev
```

Then open: **http://localhost:5181**

---

## Testing the `alwaysShowComment` Feature

### Default Behavior (Checkbox Unchecked)
1. Open the widget by clicking the FAB
2. Notice the comment field is **hidden**
3. Click **👎 Thumbs Down**
4. Comment field appears
5. Click **👍 Thumbs Up**
6. Comment field hides again

### With `alwaysShowComment` Enabled (Checkbox Checked)
1. Check the **"Always show comment field"** checkbox on the page
2. Widget will re-initialize
3. Open the widget by clicking the FAB
4. Notice the comment field is **always visible**
5. Click **👍 Thumbs Up** or **👎 Thumbs Down**
6. Comment field **stays visible** regardless of rating

---

## Testing Other Features

### docs-site Features
- Switch between Icon and Text FAB variants
- Test keyboard shortcut (Cmd/Ctrl+F) when using text variant
- Navigate between pages (Home, Getting Started, API)
- Verify feedback is page-specific

### cdn-umd Features
- Switch between Icon and Text FAB variants
- Change color palettes (emerald, indigo, rose, amber, violet, cyan)
- Verify theme colors update correctly
- Test dark mode (auto-detects system preference)

---

## Running with Custom API

Both examples support a query parameter to override the API endpoint:

```
http://localhost:5180?api=http://127.0.0.1:8787
http://localhost:5181?api=http://127.0.0.1:8787
```

This is useful for testing with a local API server.

---

## Development Tips

1. **Hot Reload**: Changes to widget source code require rebuilding:
   ```bash
   cd packages/widget
   pnpm build
   ```
   Then refresh the browser.

2. **Clear Cache**: If changes don't appear, hard refresh:
   - Mac: `Cmd + Shift + R`
   - Windows/Linux: `Ctrl + Shift + R`

3. **Debug Mode**: Add `?debug=1` to the URL or set `localStorage['fidbak:debug'] = '1'` in the browser console for verbose logging.

4. **Multiple Examples**: You can run both examples simultaneously on different ports.

---

## Troubleshooting

**Widget doesn't load:**
- Ensure widget is built: `cd packages/widget && pnpm build`
- Check browser console for errors
- Verify `node_modules/@fidbak/widget` exists in the example directory

**Types not working in docs-site:**
- Run `pnpm install` to link the local widget
- Restart TypeScript server in your IDE

**UMD bundle not found (cdn-umd):**
- Ensure `packages/widget/dist/fidbak.min.global.js` exists
- Check the console for 404 errors
- The example tries both `/@fs/...` and relative paths automatically
