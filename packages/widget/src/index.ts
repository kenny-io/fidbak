import type { FidbakAPI, InitOptions, RenderOptions, FeedbackPayload, ThemeOverrides } from './types';

// Default production API base; can be overridden via options.apiBaseUrl
const DEFAULT_API_BASE = 'https://fidbak-api.primary-account-45e.workers.dev';

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

function resolveTheme(): 'light' | 'dark' {
  const opt = STATE.options?.theme || 'auto';
  if (opt === 'light' || opt === 'dark') return opt;
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
  root.appendChild(btn);
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
  overlay.style.display = 'flex';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';
  overlay.style.padding = '16px';
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal(overlay);
  });

  const card = document.createElement('div');
  // Increase width by >=30% (from 420px -> 560px)
  card.style.width = 'min(92vw, 560px)';
  const theme = resolveTheme();
  card.style.background = theme === 'dark' ? v.colors.cardBgDark : v.colors.cardBgLight;
  card.style.borderRadius = `${v.radiusCard}px`;
  card.style.boxShadow = '0 12px 40px rgba(0,0,0,0.25)';
  card.style.padding = `${v.cardPadding}px`;
  card.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  card.style.fontFamily = v.fontFamily;
  card.style.boxSizing = 'border-box';
  card.style.maxWidth = '560px';
  card.style.maxHeight = '90vh';
  card.style.overflow = 'auto';

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
  });

  const down = document.createElement('button');
  down.type = 'button';
  down.textContent = '👎';
  down.setAttribute('aria-label', 'Thumbs down');
  styleThumb(down, theme, v);
  down.addEventListener('click', () => {
    STATE.currentRating = 'down';
    selectThumb(down, up, theme, 'down');
  });

  const commentLabel = document.createElement('div');
  commentLabel.innerHTML = 'Tell us more <span style="color:#9ca3af">(optional)</span>';
  commentLabel.style.fontSize = '14px';
  commentLabel.style.margin = '6px 0 6px 0';

  const comment = document.createElement('textarea');
  comment.rows = 4;
  comment.placeholder = 'Tell us more (optional)';
  comment.style.width = '100%';
  comment.style.background = theme === 'dark' ? '#0f0f0f' : '#fff';
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

  const emailLabel = document.createElement('div');
  emailLabel.innerHTML = 'Name / Email <span style="color:#9ca3af">(optional)</span>';
  emailLabel.style.fontSize = '14px';
  emailLabel.style.margin = '8px 0 6px 0';

  const email = document.createElement('input');
  email.type = 'email';
  email.placeholder = 'Name / Email (optional)';
  email.style.width = '100%';
  email.style.marginTop = '8px';
  email.style.background = theme === 'dark' ? '#0f0f0f' : '#fff';
  email.style.color = theme === 'dark' ? v.colors.textDark : v.colors.textLight;
  email.style.border = '1px solid ' + (theme === 'dark' ? v.colors.borderDark : v.colors.borderLight);
  email.style.borderRadius = `${v.radiusInput}px`;
  email.style.padding = '10px 12px';
  email.style.boxSizing = 'border-box';
  email.style.maxWidth = '100%';
  email.style.outline = 'none';
  email.addEventListener('focus', () => {
    email.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.35)';
  });
  email.addEventListener('blur', () => {
    email.style.boxShadow = 'none';
  });

  const emailHelp = document.createElement('div');
  emailHelp.textContent = "We'll only use this to follow up on your feedback";
  emailHelp.style.color = '#9ca3af';
  emailHelp.style.fontSize = '12px';
  emailHelp.style.marginTop = '6px';

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
        email: email.value.trim() || undefined,
      } as any; // filled by sendFeedback using page context
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
  card.appendChild(emailLabel);
  card.appendChild(email);
  card.appendChild(emailHelp);
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
    (options as any).apiBaseUrl = u.origin + (u.pathname.replace(/\/$/, '')) + (u.search || '') + (u.hash || '');
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
  const colors = {
    overlay: o.colors?.overlay || 'rgba(0,0,0,0.4)',
    cardBgLight: o.colors?.cardBgLight || '#fff',
    cardBgDark: o.colors?.cardBgDark || '#111',
    textLight: o.colors?.textLight || '#111',
    textDark: o.colors?.textDark || '#f2f2f2',
    borderLight: o.colors?.borderLight || '#e5e7eb',
    borderDark: o.colors?.borderDark || '#374151',
    focusRing: o.colors?.focusRing || 'rgba(59,130,246,0.35)',
    // Defaults to green intent for primary actions
    primaryStart: o.colors?.primaryStart || '#22c55e',
    primaryEnd: o.colors?.primaryEnd || '#16a34a',
    primaryText: o.colors?.primaryText || '#052e16',
    ghostBorderLight: o.colors?.ghostBorderLight || (o.colors?.borderLight || '#e5e7eb'),
    ghostBorderDark: o.colors?.ghostBorderDark || (o.colors?.borderDark || '#374151'),
    fabBgLight: o.colors?.fabBgLight || '#111',
    fabBgDark: o.colors?.fabBgDark || '#111',
    fabTextLight: o.colors?.fabTextLight || '#fff',
    fabTextDark: o.colors?.fabTextDark || '#fff',
    // Send pill (overrides default emerald tints)
    sendBtnBgLight: o.colors?.sendBtnBgLight,
    sendBtnBgDark: o.colors?.sendBtnBgDark,
    sendBtnBorderLight: o.colors?.sendBtnBorderLight,
    sendBtnBorderDark: o.colors?.sendBtnBorderDark,
    sendBtnTextLight: o.colors?.sendBtnTextLight,
    sendBtnTextDark: o.colors?.sendBtnTextDark,
    // Cancel pill (overrides default rose tints)
    cancelBtnBgLight: o.colors?.cancelBtnBgLight,
    cancelBtnBgDark: o.colors?.cancelBtnBgDark,
    cancelBtnBorderLight: o.colors?.cancelBtnBorderLight,
    cancelBtnBorderDark: o.colors?.cancelBtnBorderDark,
    cancelBtnTextLight: o.colors?.cancelBtnTextLight,
    cancelBtnTextDark: o.colors?.cancelBtnTextDark,
    // Thumb intent overrides
    thumbUpBgLight: o.colors?.thumbUpBgLight,
    thumbUpBgDark: o.colors?.thumbUpBgDark,
    thumbUpBorder: o.colors?.thumbUpBorder,
    thumbDownBgLight: o.colors?.thumbDownBgLight,
    thumbDownBgDark: o.colors?.thumbDownBgDark,
    thumbDownBorder: o.colors?.thumbDownBorder,
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
    const win = STATE.options?.debounceMs ?? 10 * 60 * 1000;
    return Date.now() - last < win;
  } catch {
    return false;
  }
}

function markDebounce(siteId: string, pageId: string, nearest: string) {
  try {
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
    console.error('[fidbak] invalid apiBaseUrl; must be absolute http(s) URL');
    return;
  }
  base = base.replace(/\/$/, '');
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
  } catch (e) {
    console.warn('fidbak: POST error', (e as any)?.message || e);
  }
  markDebounce(options.siteId, ctx.pageId, String(ctx.nearestHeading || ''));
}
