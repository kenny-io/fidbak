import type { FidbakAPI, InitOptions, RenderOptions, FeedbackPayload, ThemeOverrides } from './types';

// Default production API base; can be overridden via options.apiBaseUrl
const DEFAULT_API_BASE = 'https://fidbak-api-production.primary-account-45e.workers.dev';

const STATE: {
  inited: boolean;
  options?: InitOptions;
  container?: HTMLElement;
  currentRating?: 'up' | 'down';
  lastFocus?: HTMLElement | null;
} = { inited: false };

// -- debug helpers (opt-in via options.debug or localStorage['fidbak:debug']==='1')
function isDebug() {
  try { if (STATE.options?.debug) return true; } catch {}
  try { return (globalThis?.localStorage?.getItem('fidbak:debug') === '1'); } catch {}
  return false;
}
function dlog(...args: unknown[]) { if (isDebug()) console.log('[fidbak]', ...args); }
function dwarn(...args: unknown[]) { if (isDebug()) console.warn('[fidbak]', ...args); }
function derror(...args: unknown[]) { if (isDebug()) console.error('[fidbak]', ...args); }

function ensureContainer(): HTMLElement {
  if (STATE.container) return STATE.container;
  const el = document.createElement('div');
  el.id = 'fidbak-root';
  el.style.position = 'fixed';
  el.style.zIndex = '2147483000';
  // default position; overridden in applyPosition
  el.style.bottom = '16px';
  el.style.right = '16px';
  document.body.appendChild(el);
  STATE.container = el;
  return el;
}

function parseTheme() {
  const raw = (STATE.options?.theme || 'auto') as string;
  // Accept: 'light' | 'dark' | 'auto' | palette | 'mode:palette'
  let mode: 'light' | 'dark' | 'auto' = 'auto';
  let palette = 'emerald';
  if (raw.includes(':')) {
    const [m, p] = raw.split(':', 2);
    if (m === 'light' || m === 'dark' || m === 'auto') mode = m;
    if (p) palette = p as any;
  } else if (raw === 'light' || raw === 'dark' || raw === 'auto') {
    mode = raw;
  } else {
    // treat raw as palette shorthand, with auto mode
    palette = raw as any;
  }
  return { mode, palette } as const;
}

function resolveTheme(): 'light' | 'dark' {
  const { mode } = parseTheme();
  if (mode === 'light' || mode === 'dark') return mode;
  const prefersDark = matchMedia && matchMedia('(prefers-color-scheme: dark)').matches;
  return prefersDark ? 'dark' : 'light';
}

function applyPosition(el: HTMLElement) {
  const pos = STATE.options?.position || 'br';
  el.style.top = '';
  el.style.bottom = '';
  el.style.left = '';
  el.style.right = '';
  const m = '16px';
  if (pos === 'tl') {
    el.style.top = m; el.style.left = m;
  } else if (pos === 'tr') {
    el.style.top = m; el.style.right = m;
  } else if (pos === 'bl') {
    el.style.bottom = m; el.style.left = m;
  } else { // br
    el.style.bottom = m; el.style.right = m;
  }
}

function renderFAB() {
  const root = ensureContainer();
  applyPosition(root);
  root.innerHTML = '';
  const variant = STATE.options?.fabVariant || 'icon';
  if (variant === 'text') {
    root.appendChild(renderTextFAB());
  } else {
    root.appendChild(renderIconFAB());
  }
}

function renderIconFAB() {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.setAttribute('aria-label', 'Send feedback');
  const v = themeVars();
  const fabSize = v.fabSize;
  btn.style.width = `${fabSize}px`;
  btn.style.height = `${fabSize}px`;
  btn.style.borderRadius = `${Math.max(0, v.radiusThumb)}px`;
  btn.style.border = 'none';
  btn.style.cursor = 'pointer';
  const theme = resolveTheme();
  btn.style.background = theme === 'dark' ? v.colors.fabBgDark : v.colors.fabBgLight;
  btn.style.color = theme === 'dark' ? v.colors.fabTextDark : v.colors.fabTextLight;
  btn.style.boxShadow = '0 6px 18px rgba(0,0,0,0.3)';
  btn.style.fontSize = '24px';
  btn.textContent = '✱';
  btn.addEventListener('click', () => openModal(btn));
  return btn;
}

function renderTextFAB() {
  const theme = resolveTheme();
  const v = themeVars();
  const wrap = document.createElement('button');
  wrap.type = 'button';
  wrap.setAttribute('aria-label', 'Send feedback');
  wrap.style.display = 'inline-flex';
  wrap.style.alignItems = 'center';
  wrap.style.gap = '8px';
  wrap.style.border = '1px solid ' + (theme === 'dark' ? v.colors.borderDark : v.colors.borderLight);
  wrap.style.background = theme === 'dark' ? '#111' : '#f3f4f6';
  wrap.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  wrap.style.padding = '6px 10px 6px 8px';
  wrap.style.borderRadius = '9999px';
  wrap.style.cursor = 'pointer';
  wrap.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
  wrap.style.fontFamily = v.fontFamily;

  const icon = document.createElement('span');
  icon.textContent = '💬';
  icon.style.fontSize = '16px';

  const label = document.createElement('span');
  label.textContent = (STATE.options?.fabText || 'Feedback');
  label.style.fontSize = '14px';
  label.style.fontWeight = '600';

  const hotkey = document.createElement('span');
  hotkey.textContent = (STATE.options?.hotkeyLabel || 'F');
  hotkey.style.fontSize = '12px';
  hotkey.style.padding = '2px 6px';
  hotkey.style.borderRadius = '8px';
  hotkey.style.background = theme === 'dark' ? '#1f2937' : '#e5e7eb';
  hotkey.style.color = theme === 'dark' ? '#d1d5db' : '#111827';

  wrap.appendChild(icon);
  wrap.appendChild(label);
  wrap.appendChild(hotkey);
  wrap.addEventListener('click', () => openModal(wrap));
  return wrap;
}

function openModal(invoker?: HTMLElement) {
  STATE.lastFocus = (invoker as HTMLElement) || (document.activeElement as HTMLElement);
  dlog('openModal');
  // Minimal accessible modal scaffold
  const overlay = document.createElement('div');
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-label', 'Feedback dialog');
  overlay.style.position = 'fixed';
  // Make sure overlay is always on top of app content
  overlay.style.zIndex = '2147483647';
  overlay.style.inset = '0';
  const v = themeVars();
  overlay.style.background = v.colors.overlay;
  overlay.style.display = 'block';
  overlay.style.padding = '0';
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal(overlay);
  });

  const card = document.createElement('div');
  // Reduce width by ~30% for a more compact modal (from 560px -> 392px)
  card.style.width = 'min(92vw, 392px)';
  card.style.position = 'fixed';
  const theme = resolveTheme();
  card.style.background = theme === 'dark' ? v.colors.cardBgDark : v.colors.cardBgLight;
  card.style.borderRadius = `${v.radiusCard}px`;
  card.style.boxShadow = '0 12px 40px rgba(0,0,0,0.25)';
  card.style.padding = `${v.cardPadding}px`;
  card.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  card.style.fontFamily = v.fontFamily;
  card.style.boxSizing = 'border-box';
  card.style.maxWidth = '392px';
  card.style.maxHeight = '90vh';
  card.style.overflow = 'auto';

  // Place the card just above the FAB based on configured position
  const gap = 12; // space between card and fab
  const fabSize = v.fabSize;
  const margin = 16; // container margin used in applyPosition
  const pos = STATE.options?.position || 'br';
  // reset
  card.style.top = '';
  card.style.bottom = '';
  card.style.left = '';
  card.style.right = '';
  if (pos === 'tl') {
    card.style.top = `${margin + fabSize + gap}px`;
    card.style.left = `${margin}px`;
  } else if (pos === 'tr') {
    card.style.top = `${margin + fabSize + gap}px`;
    card.style.right = `${margin}px`;
  } else if (pos === 'bl') {
    card.style.bottom = `${margin + fabSize + gap}px`;
    card.style.left = `${margin}px`;
  } else {
    card.style.bottom = `${margin + fabSize + gap}px`;
    card.style.right = `${margin}px`;
  }

  // Header with title and close
  const header = document.createElement('div');
  header.style.display = 'flex';
  header.style.alignItems = 'center';
  header.style.justifyContent = 'space-between';
  header.style.marginBottom = '8px';

  const title = document.createElement('h2');
  title.textContent = 'Send your feedback';
  title.style.fontSize = '20px';
  title.style.fontWeight = '600';
  title.style.margin = '0';

  const closeX = document.createElement('button');
  closeX.setAttribute('aria-label', 'Close');
  closeX.textContent = '✕';
  closeX.style.background = theme === 'dark' ? v.colors.cardBgDark : v.colors.cardBgLight;
  closeX.style.border = '1px solid ' + (theme === 'dark' ? v.colors.borderDark : v.colors.borderLight);
  closeX.style.borderRadius = `${v.radiusClose}px`;
  closeX.style.width = '32px';
  closeX.style.height = '32px';
  closeX.style.display = 'inline-flex';
  closeX.style.alignItems = 'center';
  closeX.style.justifyContent = 'center';
  closeX.style.cursor = 'pointer';
  closeX.style.fontSize = '18px';
  closeX.style.lineHeight = '1';
  closeX.style.outlineOffset = '2px';
  closeX.style.color = theme === 'dark' ? '#ffffff' : '#111111';
  closeX.addEventListener('click', () => closeModal(overlay));

  header.appendChild(title);
  header.appendChild(closeX);

  // Per-page context subtext to make it explicit this is page-scoped
  const sub = document.createElement('p');
  sub.style.margin = '8px 0 0 0';
  sub.style.fontSize = '13px';
  sub.style.color = '#6b7280';
  sub.textContent = `Was the content on this page helpful or lacking? let us know below`;

  const rateLabel = document.createElement('div');
  rateLabel.textContent = 'How was your experience?';
  rateLabel.style.fontSize = '14px';
  rateLabel.style.margin = '8px 0 6px 0';

  const controls = document.createElement('div');
  controls.style.display = 'flex';
  controls.style.gap = '12px';
  controls.style.marginBottom = '12px';
  controls.style.flexWrap = 'wrap';

  const up = document.createElement('button');
  up.type = 'button';
  up.textContent = '👍';
  up.setAttribute('aria-label', 'Thumbs up');
  styleThumb(up, theme, v);
  up.addEventListener('click', () => {
    STATE.currentRating = 'up';
    selectThumb(up, down, theme, 'up');
    // Hide details when experience is positive
    try {
      toggleDetails(false);
    } catch {}
  });

  const down = document.createElement('button');
  down.type = 'button';
  down.textContent = '👎';
  down.setAttribute('aria-label', 'Thumbs down');
  styleThumb(down, theme, v);
  down.addEventListener('click', () => {
    STATE.currentRating = 'down';
    selectThumb(down, up, theme, 'down');
    // Show details when experience is negative
    try {
      toggleDetails(true);
    } catch {}
  });

  const commentLabel = document.createElement('div');
  commentLabel.innerHTML = 'Tell us more <span style="color:#9ca3af">(optional)</span>';
  commentLabel.style.fontSize = '14px';
  commentLabel.style.margin = '6px 0 6px 0';

  const comment = document.createElement('textarea');
  comment.rows = 4;
  comment.placeholder = 'Tell us more (optional)';
  comment.style.width = '100%';
  comment.style.background = theme === 'dark' ? v.colors.inputBgDark : v.colors.inputBgLight;
  comment.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  comment.style.border = '1px solid ' + (theme === 'dark' ? v.colors.borderDark : v.colors.borderLight);
  comment.style.borderRadius = `${v.radiusInput}px`;
  comment.style.padding = '10px 12px';
  comment.maxLength = 500;
  comment.style.boxSizing = 'border-box';
  comment.style.maxWidth = '100%';
  comment.style.resize = 'vertical';
  comment.style.minHeight = '96px';
  comment.style.outline = 'none';
  comment.addEventListener('focus', () => {
    comment.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.35)';
  });
  comment.addEventListener('blur', () => {
    comment.style.boxShadow = 'none';
  });

  const counter = document.createElement('div');
  counter.style.textAlign = 'right';
  counter.style.fontSize = '12px';
  counter.style.color = '#9ca3af';
  counter.textContent = `0/500`;
  comment.addEventListener('input', () => {
    counter.textContent = `${comment.value.length}/500`;
  });

  // Hide details by default; reveal only on thumbs down
  function toggleDetails(show: boolean) {
    const disp = show ? '' : 'none';
    commentLabel.style.display = disp;
    comment.style.display = disp;
    counter.style.display = disp;
    if (show) {
      setTimeout(() => comment.focus(), 0);
    }
  }
  toggleDetails(false);

  // removed Name/Email field

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.justifyContent = 'flex-end';
  actions.style.gap = '8px';
  actions.style.marginTop = '12px';

  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.textContent = 'Cancel';
  cancel.addEventListener('click', () => closeModal(overlay));
  styleGhost(cancel, theme, v, 'danger');

  const submit = document.createElement('button');
  submit.type = 'button';
  submit.textContent = 'Send';
  stylePrimary(submit, theme, v);
  // Renders a thank-you state inside the same modal, then auto-closes
  function showThanks() {
    try {
      card.innerHTML = '';
      const th = document.createElement('div');
      th.style.display = 'grid';
      th.style.placeItems = 'center';
      th.style.textAlign = 'center';
      th.style.padding = '28px 8px 8px 8px';
      const big = document.createElement('div');
      big.textContent = '🎉';
      big.style.fontSize = '42px';
      const h = document.createElement('h2');
      h.textContent = 'Thank you!';
      h.style.margin = '8px 0 6px 0';
      h.style.fontSize = '20px';
      h.style.fontWeight = '600';
      const p = document.createElement('p');
      p.textContent = 'We appreciate your feedback.';
      p.style.margin = '0';
      p.style.color = '#9ca3af';
      p.style.fontSize = '14px';
      const close = document.createElement('button');
      close.type = 'button';
      close.textContent = 'Close';
      close.style.marginTop = '14px';
      stylePrimary(close, theme, v);
      close.addEventListener('click', () => closeModal(overlay));
      th.appendChild(big);
      th.appendChild(h);
      th.appendChild(p);
      th.appendChild(close);
      card.appendChild(th);
      // auto-close after a short delay
      const ms = 2200;
      setTimeout(() => closeModal(overlay), ms);
    } catch {}
  }
  submit.addEventListener('click', async () => {
    const rating = STATE.currentRating;
    if (!rating) {
      submit.disabled = true;
      submit.textContent = 'Choose 👍/👎';
      setTimeout(() => {
        submit.disabled = false;
        submit.textContent = 'Send';
      }, 1200);
      return;
    }
    try {
      const payload: FeedbackPayload = {
        rating,
        comment: comment.value.trim() || undefined,
        context: {
          // filled by sendFeedback using page context
        },
      } as any;
      dlog('submit', { rating });
      await sendFeedback(payload as any);
      dlog('submit success');
      showThanks();
    } catch (err) {
      derror('submit error', (err as Error)?.message || err);
    }
  });

  controls.appendChild(up);
  controls.appendChild(down);
  actions.appendChild(cancel);
  actions.appendChild(submit);

  card.appendChild(header);
  card.appendChild(sub);
  card.appendChild(rateLabel);
  card.appendChild(controls);
  card.appendChild(commentLabel);
  card.appendChild(comment);
  card.appendChild(counter);
  card.appendChild(actions);
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  // Focus trap & keyboard
  const focusables = Array.from(
    card.querySelectorAll<HTMLElement>(
      'button, [href], input, textarea, select, [tabindex]:not([tabindex="-1"])',
    ),
  );
  const first = focusables[0] || card;
  const last = focusables[focusables.length - 1] || card;
  (first as HTMLElement).focus();
  overlay.addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      closeModal(overlay);
    } else if (e.key === 'Tab') {
      if (focusables.length === 0) return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        (last as HTMLElement).focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        (first as HTMLElement).focus();
      }
    } else if (e.key === 'ArrowLeft') {
      up.click();
    } else if (e.key === 'ArrowRight') {
      down.click();
    } else if (e.key === 'Enter' && document.activeElement === submit) {
      submit.click();
    }
  });
}

export function init(options: InitOptions) {
  // Runtime validation for required apiBaseUrl
  try {
    // Auto default when not provided by consumer
    const base = String((options as any)?.apiBaseUrl || DEFAULT_API_BASE).trim();
    const u = new URL(base);
    // Normalize: drop trailing slash
    const normalizedPath = u.pathname.replace(/\/+$/, '');
    (options as any).apiBaseUrl = u.origin + normalizedPath + (u.search || '') + (u.hash || '');
  } catch {
    console.error('[fidbak] init: apiBaseUrl must be an absolute URL, e.g. https://fidbak-api.example.com');
    return; // do not initialize without a valid API base
  }
  STATE.inited = true;
  STATE.options = options;
  dlog('init options', { ...options, webhookUrl: options.webhookUrl ? '[redacted]' : undefined });
  renderFAB();
}

export function render(_opts?: RenderOptions) {
  if (!STATE.inited) return;
  renderFAB();
}

export const fidbak: FidbakAPI = (cmd, arg) => {
  if (cmd === 'init') return init(arg as InitOptions);
  if (cmd === 'render') return render(arg as RenderOptions);
};

export default fidbak;

// -------------------- internals --------------------

function themeVars() {
  const o = (STATE.options?.themeOverrides || {}) as ThemeOverrides;
  const { palette } = parseTheme();
  const p = getThemeSpec(String(palette));
  const colors = {
    // Neutrals for overall modal and controls (keep overlay neutral so host page isn't tinted)
    overlay: o.colors?.overlay || 'rgba(0,0,0,0.4)',
    cardBgLight: o.colors?.cardBgLight || p.cardBgLight,
    cardBgDark: o.colors?.cardBgDark || p.cardBgDark,
    textLight: o.colors?.textLight || p.textLight,
    textDark: o.colors?.textDark || p.textDark,
    borderLight: o.colors?.borderLight || p.borderLight,
    borderDark: o.colors?.borderDark || p.borderDark,
    focusRing: o.colors?.focusRing || p.focusRing,
    // Inputs
    inputBgLight: (o.colors as any)?.inputBgLight || p.inputBgLight,
    inputBgDark: (o.colors as any)?.inputBgDark || p.inputBgDark,
    // Primary accents
    primaryStart: o.colors?.primaryStart || p.primaryStart,
    primaryEnd: o.colors?.primaryEnd || p.primaryEnd,
    primaryText: o.colors?.primaryText || p.primaryText,
    // Button/fab defaults
    ghostBorderLight: o.colors?.ghostBorderLight || (o.colors?.borderLight || p.ghostBorderLight),
    ghostBorderDark: o.colors?.ghostBorderDark || (o.colors?.borderDark || p.ghostBorderDark),
    fabBgLight: o.colors?.fabBgLight || p.fabBgLight,
    fabBgDark: o.colors?.fabBgDark || p.fabBgDark,
    fabTextLight: o.colors?.fabTextLight || p.fabTextLight,
    fabTextDark: o.colors?.fabTextDark || p.fabTextDark,
    // Send pill
    sendBtnBgLight: o.colors?.sendBtnBgLight || p.sendBtnBgLight,
    sendBtnBgDark: o.colors?.sendBtnBgDark || p.sendBtnBgDark,
    sendBtnBorderLight: o.colors?.sendBtnBorderLight || p.sendBtnBorderLight,
    sendBtnBorderDark: o.colors?.sendBtnBorderDark || p.sendBtnBorderDark,
    sendBtnTextLight: o.colors?.sendBtnTextLight || p.sendBtnTextLight,
    sendBtnTextDark: o.colors?.sendBtnTextDark || p.sendBtnTextDark,
    // Cancel pill (use palette-complementary defaults)
    cancelBtnBgLight: o.colors?.cancelBtnBgLight || p.cancelBtnBgLight,
    cancelBtnBgDark: o.colors?.cancelBtnBgDark || p.cancelBtnBgDark,
    cancelBtnBorderLight: o.colors?.cancelBtnBorderLight || p.cancelBtnBorderLight,
    cancelBtnBorderDark: o.colors?.cancelBtnBorderDark || p.cancelBtnBorderDark,
    cancelBtnTextLight: o.colors?.cancelBtnTextLight || p.cancelBtnTextLight,
    cancelBtnTextDark: o.colors?.cancelBtnTextDark || p.cancelBtnTextDark,
    // Thumbs
    thumbUpBgLight: o.colors?.thumbUpBgLight || p.thumbUpBgLight,
    thumbUpBgDark: o.colors?.thumbUpBgDark || p.thumbUpBgDark,
    thumbUpBorder: o.colors?.thumbUpBorder || p.thumbUpBorder,
    thumbDownBgLight: o.colors?.thumbDownBgLight || p.thumbDownBgLight,
    thumbDownBgDark: o.colors?.thumbDownBgDark || p.thumbDownBgDark,
    thumbDownBorder: o.colors?.thumbDownBorder || p.thumbDownBorder,
  } as const;
  return {
    colors,
    fontFamily:
      o.fontFamily || 'system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
    radiusCard: Math.max(0, o.radius?.card ?? 12),
    radiusInput: Math.max(0, o.radius?.input ?? 8),
    radiusButton: Math.max(0, o.radius?.button ?? 10),
    radiusThumb: Math.max(0, o.radius?.thumb ?? 10),
    radiusClose: Math.max(0, o.radius?.close ?? 8),
    cardPadding: Math.max(8, o.spacing?.cardPadding ?? 16),
    fabSize: Math.max(40, o.fab?.size ?? 56),
  } as const;
}

function getThemeSpec(name: string) {
  // Each theme defines neutrals + accents to restyle the entire modal.
  const spec: Record<string, any> = {
    emerald: {
      overlay: 'rgba(16,185,129,0.10)',
      cardBgLight: '#f0fdf4', cardBgDark: '#052e16',
      inputBgLight: '#ecfdf5', inputBgDark: '#064e3b',
      textLight: '#052e16', textDark: '#d1fae5',
      borderLight: '#bbf7d0', borderDark: '#14532d',
      focusRing: 'rgba(16,185,129,0.45)',
      primaryStart: '#22c55e', primaryEnd: '#16a34a', primaryText: '#052e16',
      ghostBorderLight: '#bbf7d0', ghostBorderDark: '#166534',
      fabBgLight: '#065f46', fabBgDark: '#10b981', fabTextLight: '#ecfdf5', fabTextDark: '#052e16',
      sendBtnBgLight: '#ecfdf5', sendBtnBorderLight: '#86efac', sendBtnTextLight: '#065f46',
      sendBtnBgDark: '#052e16', sendBtnBorderDark: '#34d399', sendBtnTextDark: '#86efac',
      cancelBtnBgLight: '#fff1f2', cancelBtnBorderLight: '#fecdd3', cancelBtnTextLight: '#9f1239',
      cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
      thumbUpBgLight: '#ecfdf5', thumbUpBgDark: '#052e16', thumbUpBorder: '#34d399',
      thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185',
    },
    indigo: {
      overlay: 'rgba(99,102,241,0.12)',
      cardBgLight: '#eef2ff', cardBgDark: '#1e1b4b',
      inputBgLight: '#eef2ff', inputBgDark: '#1e1b4b',
      textLight: '#1e1b4b', textDark: '#e0e7ff',
      borderLight: '#c7d2fe', borderDark: '#312e81',
      focusRing: 'rgba(99,102,241,0.45)',
      primaryStart: '#6366f1', primaryEnd: '#4f46e5', primaryText: '#1e1b4b',
      ghostBorderLight: '#c7d2fe', ghostBorderDark: '#4338ca',
      fabBgLight: '#3730a3', fabBgDark: '#818cf8', fabTextLight: '#eef2ff', fabTextDark: '#1e1b4b',
      sendBtnBgLight: '#eef2ff', sendBtnBorderLight: '#bfdbfe', sendBtnTextLight: '#3730a3',
      sendBtnBgDark: '#1e1b4b', sendBtnBorderDark: '#818cf8', sendBtnTextDark: '#c7d2fe',
      cancelBtnBgLight: '#fef2f2', cancelBtnBorderLight: '#fecaca', cancelBtnTextLight: '#991b1b',
      cancelBtnBgDark: '#7f1d1d', cancelBtnBorderDark: '#fca5a5', cancelBtnTextDark: '#fecaca',
      thumbUpBgLight: '#eef2ff', thumbUpBgDark: '#1e1b4b', thumbUpBorder: '#818cf8',
      thumbDownBgLight: '#fef2f2', thumbDownBgDark: '#7f1d1d', thumbDownBorder: '#fca5a5',
    },
    rose: {
      overlay: 'rgba(244,63,94,0.12)',
      cardBgLight: '#fff1f2', cardBgDark: '#4c0519',
      inputBgLight: '#fff1f2', inputBgDark: '#4c0519',
      textLight: '#4c0519', textDark: '#ffe4e6',
      borderLight: '#fecdd3', borderDark: '#7f1d1d',
      focusRing: 'rgba(244,63,94,0.45)',
      primaryStart: '#f43f5e', primaryEnd: '#e11d48', primaryText: '#4c0519',
      ghostBorderLight: '#fecdd3', ghostBorderDark: '#fb7185',
      fabBgLight: '#9d174d', fabBgDark: '#fb7185', fabTextLight: '#ffe4e6', fabTextDark: '#4c0519',
      sendBtnBgLight: '#fdf2f8', sendBtnBorderLight: '#f9a8d4', sendBtnTextLight: '#9d174d',
      sendBtnBgDark: '#4c0519', sendBtnBorderDark: '#fb7185', sendBtnTextDark: '#fecdd3',
      cancelBtnBgLight: '#eef2ff', cancelBtnBorderLight: '#c7d2fe', cancelBtnTextLight: '#3730a3',
      cancelBtnBgDark: '#1e1b4b', cancelBtnBorderDark: '#818cf8', cancelBtnTextDark: '#c7d2fe',
      thumbUpBgLight: '#fdf2f8', thumbUpBgDark: '#4c0519', thumbUpBorder: '#fb7185',
      thumbDownBgLight: '#eef2ff', thumbDownBgDark: '#1e1b4b', thumbDownBorder: '#818cf8',
    },
    amber: {
      overlay: 'rgba(245,158,11,0.12)',
      cardBgLight: '#fffbeb', cardBgDark: '#451a03',
      inputBgLight: '#fffbeb', inputBgDark: '#451a03',
      textLight: '#78350f', textDark: '#fde68a',
      borderLight: '#fcd34d', borderDark: '#78350f',
      focusRing: 'rgba(245,158,11,0.45)',
      primaryStart: '#f59e0b', primaryEnd: '#d97706', primaryText: '#78350f',
      ghostBorderLight: '#fcd34d', ghostBorderDark: '#f59e0b',
      fabBgLight: '#92400e', fabBgDark: '#f59e0b', fabTextLight: '#fffbeb', fabTextDark: '#451a03',
      sendBtnBgLight: '#fffbeb', sendBtnBorderLight: '#fcd34d', sendBtnTextLight: '#92400e',
      sendBtnBgDark: '#451a03', sendBtnBorderDark: '#fbbf24', sendBtnTextDark: '#fde68a',
      cancelBtnBgLight: '#eef2ff', cancelBtnBorderLight: '#c7d2fe', cancelBtnTextLight: '#3730a3',
      cancelBtnBgDark: '#1e1b4b', cancelBtnBorderDark: '#818cf8', cancelBtnTextDark: '#c7d2fe',
      thumbUpBgLight: '#fffbeb', thumbUpBgDark: '#451a03', thumbUpBorder: '#fbbf24',
      thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185',
    },
    violet: {
      overlay: 'rgba(139,92,246,0.12)',
      cardBgLight: '#f5f3ff', cardBgDark: '#2e1065',
      inputBgLight: '#f5f3ff', inputBgDark: '#2e1065',
      textLight: '#2e1065', textDark: '#ede9fe',
      borderLight: '#ddd6fe', borderDark: '#4c1d95',
      focusRing: 'rgba(139,92,246,0.45)',
      primaryStart: '#8b5cf6', primaryEnd: '#7c3aed', primaryText: '#2e1065',
      ghostBorderLight: '#ddd6fe', ghostBorderDark: '#a78bfa',
      fabBgLight: '#6d28d9', fabBgDark: '#a78bfa', fabTextLight: '#f5f3ff', fabTextDark: '#2e1065',
      sendBtnBgLight: '#f5f3ff', sendBtnBorderLight: '#ddd6fe', sendBtnTextLight: '#6d28d9',
      sendBtnBgDark: '#2e1065', sendBtnBorderDark: '#a78bfa', sendBtnTextDark: '#ddd6fe',
      cancelBtnBgLight: '#ecfeff', cancelBtnBorderLight: '#a5f3fc', cancelBtnTextLight: '#155e75',
      cancelBtnBgDark: '#083344', cancelBtnBorderDark: '#22d3ee', cancelBtnTextDark: '#a5f3fc',
      thumbUpBgLight: '#f5f3ff', thumbUpBgDark: '#2e1065', thumbUpBorder: '#a78bfa',
      thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185',
    },
    cyan: {
      overlay: 'rgba(6,182,212,0.12)',
      cardBgLight: '#ecfeff', cardBgDark: '#083344',
      inputBgLight: '#ecfeff', inputBgDark: '#083344',
      textLight: '#083344', textDark: '#cffafe',
      borderLight: '#a5f3fc', borderDark: '#164e63',
      focusRing: 'rgba(6,182,212,0.45)',
      primaryStart: '#06b6d4', primaryEnd: '#0891b2', primaryText: '#083344',
      ghostBorderLight: '#a5f3fc', ghostBorderDark: '#22d3ee',
      fabBgLight: '#155e75', fabBgDark: '#22d3ee', fabTextLight: '#ecfeff', fabTextDark: '#083344',
      sendBtnBgLight: '#ecfeff', sendBtnBorderLight: '#a5f3fc', sendBtnTextLight: '#155e75',
      sendBtnBgDark: '#083344', sendBtnBorderDark: '#22d3ee', sendBtnTextDark: '#a5f3fc',
      cancelBtnBgLight: '#fff1f2', cancelBtnBorderLight: '#fecdd3', cancelBtnTextLight: '#9f1239',
      cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
      thumbUpBgLight: '#ecfeff', thumbUpBgDark: '#083344', thumbUpBorder: '#22d3ee',
      thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185',
    },
    slate: {
      overlay: 'rgba(100,116,139,0.12)',
      cardBgLight: '#f1f5f9', cardBgDark: '#0f172a',
      inputBgLight: '#f8fafc', inputBgDark: '#0f172a',
      textLight: '#0f172a', textDark: '#e2e8f0',
      borderLight: '#cbd5e1', borderDark: '#334155',
      focusRing: 'rgba(100,116,139,0.45)',
      primaryStart: '#64748b', primaryEnd: '#475569', primaryText: '#0f172a',
      ghostBorderLight: '#cbd5e1', ghostBorderDark: '#94a3b8',
      fabBgLight: '#1f2937', fabBgDark: '#94a3b8', fabTextLight: '#f1f5f9', fabTextDark: '#0f172a',
      sendBtnBgLight: '#f1f5f9', sendBtnBorderLight: '#cbd5e1', sendBtnTextLight: '#334155',
      sendBtnBgDark: '#0f172a', sendBtnBorderDark: '#94a3b8', sendBtnTextDark: '#cbd5e1',
      cancelBtnBgLight: '#fff1f2', cancelBtnBorderLight: '#fecdd3', cancelBtnTextLight: '#9f1239',
      cancelBtnBgDark: '#4c0519', cancelBtnBorderDark: '#fb7185', cancelBtnTextDark: '#fecdd3',
      thumbUpBgLight: '#f1f5f9', thumbUpBgDark: '#0f172a', thumbUpBorder: '#94a3b8',
      thumbDownBgLight: '#fff1f2', thumbDownBgDark: '#4c0519', thumbDownBorder: '#fb7185',
    },
  };
  return spec[name] || spec['emerald'];
}

// Minimal style helpers (keep bundle tiny and dependency-free)
function styleThumb(btn: HTMLButtonElement, theme: 'light' | 'dark', v = themeVars()) {
  btn.style.fontSize = '20px';
  btn.style.width = '44px';
  btn.style.height = '44px';
  btn.style.borderRadius = `${v.radiusThumb}px`;
  btn.style.border = '2px solid ' + (theme === 'dark' ? v.colors.borderDark : v.colors.borderLight);
  btn.style.background = theme === 'dark' ? '#0f0f0f' : '#fff';
  btn.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  btn.style.display = 'inline-flex';
  btn.style.alignItems = 'center';
  btn.style.justifyContent = 'center';
  btn.style.cursor = 'pointer';
  btn.style.transition = 'box-shadow .15s ease, border-color .15s ease, background .15s ease';
  btn.addEventListener('focus', () => (btn.style.boxShadow = `0 0 0 3px ${themeVars().colors.focusRing}`));
  btn.addEventListener('blur', () => (btn.style.boxShadow = 'none'));
}

function selectThumb(
  active: HTMLButtonElement,
  other: HTMLButtonElement,
  theme: 'light' | 'dark',
  intent: 'up' | 'down',
) {
  const v = themeVars();
  const upBgLight = v.colors.thumbUpBgLight || '#ecfdf5'; // emerald-50
  const upBgDark = v.colors.thumbUpBgDark || '#052e16';  // emerald-950
  const upBorder = v.colors.thumbUpBorder || '#34d399';  // emerald-400
  const downBgLight = v.colors.thumbDownBgLight || '#fef2f2'; // rose-50
  const downBgDark = v.colors.thumbDownBgDark || '#4c0519';  // rose-950
  const downBorder = v.colors.thumbDownBorder || '#f87171';  // rose-400

  if (intent === 'up') {
    active.style.borderColor = upBorder;
    active.style.background = theme === 'dark' ? upBgDark : upBgLight;
  } else {
    active.style.borderColor = downBorder;
    active.style.background = theme === 'dark' ? downBgDark : downBgLight;
  }
  other.style.borderColor = theme === 'dark' ? '#374151' : '#e5e7eb';
  other.style.background = theme === 'dark' ? '#0f0f0f' : '#fff';
}

function styleGhost(
  btn: HTMLButtonElement,
  theme: 'light' | 'dark',
  v = themeVars(),
  variant: 'default' | 'danger' = 'default',
) {
  btn.style.padding = '10px 14px';
  btn.style.borderRadius = `${v.radiusButton}px`;
  if (variant === 'danger') {
    const bg = theme === 'dark'
      ? (v.colors.cancelBtnBgDark || '#4c0519')
      : (v.colors.cancelBtnBgLight || '#fef2f2');
    const border = theme === 'dark'
      ? (v.colors.cancelBtnBorderDark || '#fb7185')
      : (v.colors.cancelBtnBorderLight || '#fecdd3');
    const text = theme === 'dark'
      ? (v.colors.cancelBtnTextDark || '#fecdd3')
      : (v.colors.cancelBtnTextLight || '#9f1239');
    btn.style.border = `1px solid ${border}`;
    btn.style.background = bg;
    btn.style.color = text;
  } else {
    btn.style.border = '1px solid ' + (theme === 'dark' ? v.colors.ghostBorderDark : v.colors.ghostBorderLight);
    btn.style.background = 'transparent';
    btn.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  }
  btn.style.cursor = 'pointer';
}

function stylePrimary(btn: HTMLButtonElement, theme: 'light' | 'dark', v = themeVars()) {
  btn.style.padding = '10px 14px';
  btn.style.borderRadius = `${v.radiusButton}px`;
  // Light greenish pill with green text
  const bg = theme === 'dark'
    ? (v.colors.sendBtnBgDark || '#052e16')
    : (v.colors.sendBtnBgLight || '#ecfdf5');
  const border = theme === 'dark'
    ? (v.colors.sendBtnBorderDark || '#34d399')
    : (v.colors.sendBtnBorderLight || '#86efac');
  const text = theme === 'dark'
    ? (v.colors.sendBtnTextDark || '#86efac')
    : (v.colors.sendBtnTextLight || '#065f46');
  btn.style.border = `1px solid ${border}`;
  btn.style.background = bg;
  btn.style.color = text;
  btn.style.fontWeight = '600';
  btn.style.cursor = 'pointer';
}

function closeModal(overlay: HTMLElement) {
  try {
    if (overlay && overlay.parentElement) overlay.parentElement.removeChild(overlay);
  } catch {}
  // restore focus back to the invoker if available
  try {
    STATE.currentRating = undefined;
    STATE.lastFocus?.focus();
  } catch {}
}

function getPageContext(options: InitOptions, ro?: RenderOptions) {
  const loc = window.location;
  const url = new URL(loc.href);
  if (!options.includeQuery) {
    url.search = '';
  }
  const pageId = ro?.pageId || (options.includeQuery ? url.pathname + url.search : url.pathname);
  const title = ro?.title || document.title || '';

  const scrollPct = (() => {
    const b = document.documentElement;
    const height = b.scrollHeight - b.clientHeight;
    if (height <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((b.scrollTop / height) * 100)));
  })();

  const mid = window.innerHeight / 2 + (document.documentElement.scrollTop || document.body.scrollTop || 0);
  const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6')) as HTMLElement[];
  let nearest = '';
  for (const h of headings) {
    if (h.offsetTop <= mid) nearest = h.innerText.trim();
  }

  let selected = '';
  try {
    selected = (window.getSelection()?.toString() || '').slice(0, 500);
  } catch {}

  return {
    pageId,
    title,
    url: url.toString(),
    referrer: document.referrer || '',
    scrollPct,
    nearestHeading: nearest,
    selectedText: selected,
    ua: navigator.userAgent,
  } as const;
}

function debounceKey(siteId: string, pageId: string, nearest: string) {
  return `fidbak:last:${siteId}:${pageId}:${nearest}`;
}

function withinDebounce(siteId: string, pageId: string, nearest: string) {
  try {
    const key = debounceKey(siteId, pageId, nearest);
    const raw = localStorage.getItem(key);
    if (!raw) return false;
    const last = parseInt(raw, 10);
    const win = STATE.options?.debounceMs ?? 0;
    if (win <= 0) return false;
    return Date.now() - last < win;
  } catch {
    return false;
  }
}

function markDebounce(siteId: string, pageId: string, nearest: string) {
  try {
    const win = STATE.options?.debounceMs ?? 0;
    if (win <= 0) return; // disabled
    localStorage.setItem(debounceKey(siteId, pageId, nearest), String(Date.now()));
  } catch {}
}

async function hmacSHA256Hex(secret: string, payload: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  const bytes = new Uint8Array(sig);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sendFeedback(partial: {
  rating: 'up' | 'down';
  comment?: string;
  email?: string;
}) {
  const options = STATE.options!;
  const ctx = getPageContext(options);

  if (withinDebounce(options.siteId, ctx.pageId, String(ctx.nearestHeading || ''))) {
    return; // drop duplicate within window
  }

  const payload: FeedbackPayload = {
    siteId: options.siteId,
    pageId: ctx.pageId,
    rating: partial.rating,
    comment: partial.comment,
    email: partial.email,
    context: {
      title: ctx.title,
      url: ctx.url,
      referrer: ctx.referrer,
      scrollPct: ctx.scrollPct,
      nearestHeading: ctx.nearestHeading,
      selectedText: ctx.selectedText,
      ua: ctx.ua,
      platform: 'web',
    },
    destinations: Array.isArray(options.webhookUrl)
      ? options.webhookUrl
      : options.webhookUrl
      ? [options.webhookUrl]
      : undefined,
    webhookSecret: options.webhookSecret,
    policy: options.policy,
    themeOverrides: options.themeOverrides,
  };

  const body = JSON.stringify(payload);
  // apiBaseUrl is validated in init(); normalize here as a safeguard
  let base = String(options.apiBaseUrl || '').trim();
  if (!/^https?:\/\//.test(base)) {
    const msg = '[fidbak] invalid apiBaseUrl; must be absolute http(s) URL';
    derror(msg);
    throw new Error(msg);
  }
  base = base.replace(/\/+$/, '');
  const url = `${base}/v1/feedback`;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (options.signSecret) {
    headers['x-fidbak-signature'] = await hmacSHA256Hex(options.signSecret, body);
  }
  try {
    // debug logs to help during local testing
    dlog('POST', url, payload);
    const resp = await fetch(url, { method: 'POST', headers, body, keepalive: true });
    dlog('POST resp', resp.status);
    if (!resp.ok) {
      const msg = `[fidbak] POST failed: ${resp.status}`;
      derror(msg);
      throw new Error(msg);
    }
  } catch (e) {
    console.warn('fidbak: POST error', (e as any)?.message || e);
    throw e;
  }
  // Only mark success to prevent blocking future attempts after failures
  markDebounce(options.siteId, ctx.pageId, String(ctx.nearestHeading || ''));
}
