export interface Env {
  DB?: D1Database; // optional binding
  FIDBAK_DASHBOARD_BASE?: string; // used in Slack footer link
  FIDBAK_SLACK_WEBHOOK?: string; // fallback global webhook
  FIDBAK_SLACK_CHANNEL?: string; // optional default channel
}

type FeedbackRow = {
  id: string;
  site_id: string;
  page_id: string;
  rating: 'up' | 'down';
  comment?: string;
  email?: string;
  context_json: unknown;
  ip_hash: string;
  created_at: string;
};

// In-memory storage for dev
const MEM: { feedback: FeedbackRow[] } = { feedback: [] };
const RATE: Map<string, number[]> = new Map(); // key = `${ip}|${siteId}` -> timestamps

// Temporary site registry in-memory for dev. Replace with D1 `sites` table.
const SITES: Record<string, { name: string; hmac_secret?: string; cors?: string[] }> = {
  'demo-site': {
    name: 'Demo Site',
    // In real env, require server-side signing using per-site secret not shared with client.
    // For dev we can skip or set a known secret.
    // hmac_secret: 'dev-secret',
    cors: ['http://localhost:5173', 'http://localhost:5175', 'http://localhost:5181'],
  },
};

function json(data: unknown, init: ResponseInit = {}, origin?: string) {
  const h = new Headers(init.headers);
  h.set('content-type', 'application/json; charset=utf-8');
  // Dev CORS; later replace with per-site allowlist
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response(JSON.stringify(data), { ...init, headers: h });
}

function cors(request: Request): { origin: string | undefined; isPreflight: boolean } {
  const origin = request.headers.get('origin') || undefined;
  const isPreflight = request.method === 'OPTIONS';
  return { origin, isPreflight };
}

function ok(init: ResponseInit = {}, origin?: string) {
  const h = new Headers(init.headers);
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response('ok', { ...init, headers: h });
}

function notFound(origin?: string) {
  const h = new Headers();
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response('Not found', { status: 404, headers: h });
}

function bad(msg: string, origin?: string) {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response(JSON.stringify({ error: msg }), { status: 400, headers: h });
}

function ipFrom(req: Request) {
  return (
    req.headers.get('cf-connecting-ip') ||
    req.headers.get('x-forwarded-for') ||
    (req as any).ip ||
    ''
  );
}

function hashIp(ip: string) {
  // simple stable hash for dev; will be replaced with daily rotating salt
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return String(h);
}

function rateLimit(ip: string, siteId: string, limit = 8, windowMs = 60_000) {
  const key = `${ip}|${siteId}`;
  const now = Date.now();
  const arr = RATE.get(key) || [];
  const kept = arr.filter((t) => now - t < windowMs);
  if (kept.length >= limit) return false;
  kept.push(now);
  RATE.set(key, kept);
  return true;
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

function corsForSite(siteId: string | undefined, origin: string | undefined): string | undefined {
  if (!origin) return '*';
  if (!siteId) return origin;
  const site = SITES[siteId];
  if (!site?.cors) return origin; // permissive in dev
  return site.cors.includes(origin) ? origin : undefined;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { origin, isPreflight } = cors(request);

    if (isPreflight) {
      const h = new Headers({
        'access-control-allow-origin': origin || '*',
        'access-control-allow-methods': 'GET,POST,OPTIONS',
        'access-control-allow-headers': 'content-type,x-fidbak-signature',
      });
      return new Response(null, { status: 204, headers: h });
    }

    if (url.pathname === '/' || url.pathname === '/v1/health') {
      return json({ ok: true }, {}, origin || '*');
    }

    if (url.pathname === '/v1/feedback' && request.method === 'POST') {
      const ip = ipFrom(request);
      // Read raw body string for stable HMAC
      let raw = '';
      try {
        raw = await request.text();
      } catch {
        return bad('invalid body', origin || '*');
      }
      let body: any;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return bad('invalid json', origin || '*');
      }
      const { siteId, pageId, rating } = body || {};
      if (!siteId || !pageId || (rating !== 'up' && rating !== 'down')) {
        return bad('missing fields', origin || '*');
      }
      // Per-request policy from client (optional)
      const policy = (body && typeof body.policy === 'object') ? body.policy as any : undefined;
      // CORS allow: prioritize policy.corsAllow if provided, otherwise site config
      let allow = corsForSite(siteId, origin || undefined);
      if (origin && policy?.corsAllow && Array.isArray(policy.corsAllow)) {
        allow = policy.corsAllow.includes(origin) ? origin : allow;
      }
      if (!allow) {
        return new Response('Forbidden', { status: 403 });
      }
      // Optional HMAC verification if site has secret configured
      const site = await getSite(env, siteId);
      const sig = request.headers.get('x-fidbak-signature') || '';
      const secret = site?.hmac_secret;
      const requireHmac = policy?.requireHmac === true || !!secret;
      if (requireHmac && secret) {
        const expect = await hmacSHA256Hex(secret, raw);
        if (sig.toLowerCase() !== expect.toLowerCase()) {
          return json({ accepted: false, reason: 'bad_signature' }, { status: 401 }, allow);
        }
      } else if (requireHmac) {
        // requireHmac true but no site secret -> reject
        return json({ accepted: false, reason: 'hmac_required' }, { status: 401 }, allow);
      }
      // IP allow list (if provided in policy)
      if (policy?.ipAllow && Array.isArray(policy.ipAllow) && policy.ipAllow.length > 0) {
        if (!policy.ipAllow.includes(ip)) {
          return json({ accepted: false, reason: 'ip_forbidden' }, { status: 403 }, allow);
        }
      }
      if (!rateLimit(ip, siteId)) {
        return json({ accepted: false, reason: 'rate_limited' }, { status: 429 }, allow);
      }
      // Apply policy-defined rate limit if provided (cap values for safety)
      if (policy?.rateLimit) {
        const windowMs = Math.max(1_000, Math.min(10 * 60_000, Number(policy.rateLimit.windowMs || 60_000)));
        const max = Math.max(1, Math.min(120, Number(policy.rateLimit.max || 8)));
        const key = `${ip}|${siteId}|policy`;
        const now = Date.now();
        const arr = RATE.get(key) || [];
        const kept = arr.filter((t) => now - t < windowMs);
        if (kept.length >= max) {
          return json({ accepted: false, reason: 'rate_limited_policy' }, { status: 429 }, allow);
        }
        kept.push(now);
        RATE.set(key, kept);
      }
      const row: FeedbackRow = {
        id: crypto.randomUUID(),
        site_id: siteId,
        page_id: pageId,
        rating,
        comment: typeof body.comment === 'string' ? body.comment.slice(0, 5000) : undefined,
        email: typeof body.email === 'string' ? body.email.slice(0, 320) : undefined,
        context_json: body.context || {},
        ip_hash: hashIp(ip),
        created_at: new Date().toISOString(),
      };
      await storeFeedback(env, row);
      const destinations = Array.isArray(body.destinations)
        ? (body.destinations as string[])
        : body.destinations
        ? [body.destinations]
        : undefined;
      ctx.waitUntil(
        fanout(
          env,
          row,
          destinations,
          typeof body.webhookSecret === 'string' ? body.webhookSecret : undefined,
          policy,
        ).catch(() => {}),
      );
      return json({ accepted: true, id: row.id }, { status: 202 }, allow);
    }

    // GET /v1/sites/:id/feedback
    const match = url.pathname.match(/^\/v1\/sites\/([^/]+)\/feedback$/);
    if (match && request.method === 'GET') {
      const siteId = decodeURIComponent(match[1] || '');
      const allow = corsForSite(siteId, origin || undefined) || origin || '*';
      const rating = url.searchParams.get('rating') as 'up' | 'down' | null;
      const q = url.searchParams.get('q');
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10)));
      const offset = Math.max(0, parseInt(url.searchParams.get('offset') || '0', 10));

      let items: FeedbackRow[];
      let total = 0;
      if (env.DB) {
        try {
          const stmt = env.DB.prepare(
            `SELECT id, site_id, page_id, rating, comment, email, context_json, ip_hash, created_at
             FROM feedback WHERE site_id = ?
             ${rating ? 'AND rating = ?' : ''}
             ${q ? 'AND comment LIKE ?' : ''}
             ORDER BY datetime(created_at) DESC
             LIMIT ? OFFSET ?`,
          );
          const binds: any[] = [siteId];
          if (rating) binds.push(rating);
          if (q) binds.push(`%${q}%`);
          binds.push(limit, offset);
          const res = await stmt.bind(...binds).all<FeedbackRow>();
          items = (res.results as any) || [];

          // Compute total with COUNT(*) using same filters
          const countStmt = env.DB.prepare(
            `SELECT COUNT(*) AS c FROM feedback WHERE site_id = ?
             ${rating ? 'AND rating = ?' : ''}
             ${q ? 'AND comment LIKE ?' : ''}`,
          );
          const countRes = await countStmt.bind(...[siteId, ...(rating ? [rating] : []), ...(q ? [`%${q}%`] : [])]).first<{ c: number }>();
          total = Number(countRes?.c || 0);
        } catch {
          // Fallback to memory if DB not migrated yet
          let all = MEM.feedback.filter((f) => f.site_id === siteId);
          if (rating) all = all.filter((f) => f.rating === rating);
          if (q) all = all.filter((f) => (f.comment || '').toLowerCase().includes(q.toLowerCase()));
          total = all.length;
          items = all.slice(offset, offset + limit);
        }
      } else {
        let all = MEM.feedback.filter((f) => f.site_id === siteId);
        if (rating) all = all.filter((f) => f.rating === rating);
        if (q) all = all.filter((f) => (f.comment || '').toLowerCase().includes(q.toLowerCase()));
        total = all.length;
        items = all.slice(offset, offset + limit);
      }
      return json({ items, total, nextOffset: Math.min(total, offset + items.length) }, {}, allow);
    }

    // GET /v1/sites/:id/summary?days=7
    const matchSummary = url.pathname.match(/^\/v1\/sites\/([^/]+)\/summary$/);
    if (matchSummary && request.method === 'GET') {
      const siteId = decodeURIComponent(matchSummary[1] || '');
      const allow = corsForSite(siteId, origin || undefined) || origin || '*';
      const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get('days') || '7', 10)));
      const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

      if (env.DB) {
        try {
          const totalRow = await env.DB.prepare(
            'SELECT COUNT(*) as c FROM feedback WHERE site_id = ?',
          ).bind(siteId).first<{ c: number }>();
          const windowRow = await env.DB.prepare(
            `SELECT SUM(CASE WHEN rating='up' THEN 1 ELSE 0 END) as up,
                    SUM(CASE WHEN rating='down' THEN 1 ELSE 0 END) as down
             FROM feedback WHERE site_id = ? AND datetime(created_at) >= datetime(?)`,
          ).bind(siteId, sinceIso).first<{ up: number; down: number }>();
          const up = Number(windowRow?.up || 0);
          const down = Number(windowRow?.down || 0);
          const total = Number(totalRow?.c || 0);
          return json({ total, lastN: { days, up, down, total: up + down } }, {}, allow);
        } catch {}
      }
      // Memory fallback
      const all = MEM.feedback.filter((f) => f.site_id === siteId);
      const total = all.length;
      const since = new Date(sinceIso).getTime();
      const windowItems = all.filter((f) => new Date(f.created_at).getTime() >= since);
      const up = windowItems.filter((f) => f.rating === 'up').length;
      const down = windowItems.filter((f) => f.rating === 'down').length;
      return json({ total, lastN: { days, up, down, total: up + down } }, {}, allow);
    }

    return notFound(origin || '*');
  },
} satisfies ExportedHandler<Env>;

// ---------- storage helpers ----------
async function getSite(env: Env, siteId: string): Promise<{ hmac_secret?: string; cors?: string[] } | undefined> {
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        'SELECT hmac_secret, cors_json as cors_json FROM sites WHERE id = ?',
      ).bind(siteId).first<{ hmac_secret?: string; cors_json?: string }>();
      if (row) {
        return { hmac_secret: row.hmac_secret, cors: row.cors_json ? JSON.parse(row.cors_json) : undefined };
      }
    } catch {}
  }
  return SITES[siteId];
}

async function storeFeedback(env: Env, row: FeedbackRow) {
  if (env.DB) {
    try {
      await env.DB.prepare(
        `INSERT INTO feedback (id, site_id, page_id, rating, comment, email, context_json, ip_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          row.id,
          row.site_id,
          row.page_id,
          row.rating,
          row.comment || null,
          row.email || null,
          JSON.stringify(row.context_json || {}),
          row.ip_hash,
          row.created_at,
        )
        .run();
      return;
    } catch {}
  }
  MEM.feedback.unshift(row);
}

// ---------- fanout ----------
async function fanout(
  env: Env,
  row: FeedbackRow,
  destinations?: string[],
  webhookSecret?: string,
  policy?: any,
) {
  const all: string[] = [];
  if (Array.isArray(destinations)) all.push(...destinations);
  if (env.FIDBAK_SLACK_WEBHOOK) all.push(env.FIDBAK_SLACK_WEBHOOK);

  await Promise.all(
    all.map(async (url) => {
      // basic redaction for logs
      const redacted = url.replace(/(https:\/\/hooks\.slack\.com\/services\/)[^/]+\/[^/]+\/.+/, '$1***');
      try {
        if (/hooks\.slack\.com\/services\//.test(url)) {
          console.log('fidbak: posting to Slack', redacted);
          await postSlack(url, env, row, policy);
        } else {
          const body = JSON.stringify({ type: 'fidbak.feedback.v1', data: row });
          const headers: Record<string, string> = { 'content-type': 'application/json' };
          if (webhookSecret) {
            headers['x-fidbak-signature'] = await hmacSHA256Hex(webhookSecret, body);
          }
          const resp = await fetch(url, { method: 'POST', headers, body });
          if (!resp.ok) {
            console.warn('fidbak: webhook non-2xx', redacted, resp.status);
            try { console.warn('fidbak: webhook resp', await resp.text()); } catch {}
          }
        }
      } catch (e) {
        console.warn('fidbak: webhook error', redacted, (e as any)?.message || e);
      }
    }),
  );
}

function makeSlackBlocks(env: Env, row: FeedbackRow) {
  const ctx: any = row.context_json || {};
  const rating = row.rating === 'up' ? '👍' : '👎';
  const title = ctx.title || '';
  const url = ctx.url || row.page_id;
  const ref = ctx.referrer ? `Ref: ${ctx.referrer}` : '';
  const scroll = typeof ctx.scrollPct === 'number' ? `Scroll: ${ctx.scrollPct}%` : '';
  const subtitle = [title, row.page_id].filter(Boolean).join(' • ');
  const footerLink = env.FIDBAK_DASHBOARD_BASE
    ? `${env.FIDBAK_DASHBOARD_BASE}/?siteId=${encodeURIComponent(row.site_id)}&id=${encodeURIComponent(row.id)}`
    : '';
  const footer = [row.email || '', footerLink ? `<${footerLink}|Open>` : ''].filter(Boolean).join(' • ');
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: `${rating} Feedback on ${row.page_id}` } },
    ...(row.comment ? [{ type: 'section', text: { type: 'mrkdwn', text: `*Comment*\n${row.comment}` } }] : []),
    { type: 'section', text: { type: 'mrkdwn', text: `*Page* <${url}|${subtitle}>` } },
    ...(ref || scroll ? [{ type: 'context', elements: [{ type: 'mrkdwn', text: [ref, scroll].filter(Boolean).join(' • ') }] }] : []),
    ...(footer ? [{ type: 'context', elements: [{ type: 'mrkdwn', text: footer }] }] : []),
  ];
  return blocks;
}

async function postSlack(webhook: string, env: Env, row: FeedbackRow, policy?: any) {
  const blocks = makeSlackBlocks(env, row);
  const text = `${row.rating === 'up' ? '👍' : '👎'} Feedback on ${row.page_id}${row.comment ? `: ${row.comment}` : ''}`;
  const payload: any = { text, blocks, username: 'fidbak', icon_emoji: ':speech_balloon:' };
  const channel = policy?.slackChannel || env.FIDBAK_SLACK_CHANNEL;
  if (channel) payload.channel = channel;
  await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(async (r) => {
    const body = await r.text().catch(() => '');
    console.log('fidbak: slack response', r.status, body);
    if (!r.ok) {
      console.warn('fidbak: slack webhook non-2xx', r.status);
    }
  }).catch((e) => {
    console.warn('fidbak: slack webhook error', e?.message || e);
  });
}
