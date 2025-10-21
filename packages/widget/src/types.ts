export type Palette = 'default' | 'emerald' | 'indigo' | 'rose' | 'amber' | 'violet' | 'cyan' | 'slate';
export type Theme =
  | 'light'
  | 'dark'
  | 'auto'
  | Palette
  | `light:${Palette}`
  | `dark:${Palette}`
  | `auto:${Palette}`;
export type Position = 'tl' | 'tr' | 'bl' | 'br';

export interface InitOptions {
  siteId: string;
  theme?: Theme;
  position?: Position;
  draggable?: boolean;
  includeQuery?: boolean;
  apiBaseUrl?: string; // Optional; defaults to production API; override for testing
  signSecret?: string; // optional client-side signing (dev only)
  webhookUrl?: string | string[]; // optional direct webhook fanout destinations
  webhookSecret?: string; // optional HMAC secret used to sign webhook body
  debounceMs?: number; // default 10 * 60 * 1000
  policy?: PolicyOptions; // client-provided behavior controls
  /** Enable verbose client logs (also enabled if localStorage['fidbak:debug']=== '1'). */
  debug?: boolean;
  themeOverrides?: ThemeOverrides; // allow brands to customize look & feel
  /** Choose the Floating Action Button variant. Defaults to 'icon'. */
  fabVariant?: 'icon' | 'text';
  /** Text to show inside the text FAB. Defaults to 'Feedback'. */
  fabText?: string;
  /** Small hotkey label badge text shown on the right in text FAB. Defaults to 'F'. */
  hotkeyLabel?: string;
  /** If true, intercept Cmd/Ctrl+F to open the modal when using the 'text' FAB variant. Defaults to true. */
  interceptFind?: boolean;
  /** If true, always show the comment field. If false, only show it when user clicks thumbs down. Defaults to false. */
  alwaysShowComment?: boolean;
}

export interface RenderOptions {
  pageId?: string;
  platform?: string;
  title?: string;
}

export interface FeedbackPayload {
  siteId: string;
  pageId: string;
  rating: 'up' | 'down';
  comment?: string;
  email?: string;
  context: Record<string, unknown>;
  destinations?: string[];
  webhookSecret?: string;
  policy?: PolicyOptions;
  themeOverrides?: ThemeOverrides;
}

export interface PolicyOptions {
  // Rate limit applied by server per IP+siteId
  rateLimit?: {
    windowMs?: number; // default 60_000
    max?: number; // default 8
  };
  // Server CORS allowance; if absent server may fallback to its config
  corsAllow?: string[]; // list of allowed origins
  // Server IP allow-list (exact match for now)
  ipAllow?: string[];
  // Server requirement for HMAC verification on client->server
  requireHmac?: boolean;
}

export interface ThemeOverrides {
  fontFamily?: string;
  radius?: {
    card?: number;
    input?: number;
    button?: number;
    thumb?: number;
    close?: number;
  };
  colors?: {
    overlay?: string;
    cardBgLight?: string;
    cardBgDark?: string;
    textLight?: string;
    textDark?: string;
    borderLight?: string;
    borderDark?: string;
    focusRing?: string; // rgba/hex
    // Legacy gradient primary (no longer used by default but still honored)
    primaryStart?: string; // gradient start
    primaryEnd?: string;   // gradient end
    primaryText?: string;
    // Send button pill (light/dark)
    sendBtnBgLight?: string;
    sendBtnBgDark?: string;
    sendBtnBorderLight?: string;
    sendBtnBorderDark?: string;
    sendBtnTextLight?: string;
    sendBtnTextDark?: string;
    // Cancel button pill (light/dark)
    cancelBtnBgLight?: string;
    cancelBtnBgDark?: string;
    cancelBtnBorderLight?: string;
    cancelBtnBorderDark?: string;
    cancelBtnTextLight?: string;
    cancelBtnTextDark?: string;
    // Thumb selection intent colors
    thumbUpBgLight?: string;
    thumbUpBgDark?: string;
    thumbUpBorder?: string;
    thumbDownBgLight?: string;
    thumbDownBgDark?: string;
    thumbDownBorder?: string;
    ghostBorderLight?: string;
    ghostBorderDark?: string;
    fabBgLight?: string;
    fabBgDark?: string;
    fabTextLight?: string;
    fabTextDark?: string;
  };
  spacing?: {
    cardPadding?: number; // px
  };
  fab?: {
    size?: number; // px
  };
}

export type FidbakAPI = (
  cmd: 'init' | 'render',
  arg: InitOptions | RenderOptions,
) => void;
