export interface Env {
  DB?: D1Database; // optional binding
  FIDBAK_DASHBOARD_BASE?: string; // used in Slack footer link
  // Deprecated: global webhook removed; use per-site managed webhooks instead
  FIDBAK_SLACK_WEBHOOK?: string; // no longer used
  FIDBAK_SLACK_CHANNEL?: string; // no longer used
  // Clerk config for JWT verification
  CLERK_ISSUER?: string; // e.g. https://your-subdomain.clerk.accounts.dev
  CLERK_JWKS_URL?: string; // e.g. https://your-subdomain.clerk.accounts.dev/.well-known/jwks.json
  CLERK_AUDIENCE?: string; // optional audience check
  // Optional secondary issuer support (e.g., allow local dev tokens against prod API)
  CLERK_ISSUER_2?: string;
  CLERK_JWKS_URL_2?: string;
  // Default dashboard origin to auto-allowlist on site creation
  FIDBAK_DASH_ORIGIN?: string; // e.g. https://fidbak-dash.pages.dev
}

// New: list sites by owner using sub (preferred) then email
async function listSitesByOwner(
  env: Env,
  owner: { sub?: string; email?: string },
): Promise<Array<{
  id: string;
  name?: string;
  owner_email?: string | null;
  owner_user_id?: string | null;
  cors: string[];
  created_at: string;
  verified_at?: string | null;
  feedback_count?: number;
}>> {
  const byEmail = async (email?: string) => listSites(env, email);
  if (env.DB && owner.sub) {
    try {
      const sql = `SELECT s.id, s.name, s.owner_email, s.owner_user_id, s.cors_json, s.created_at, s.verified_at,
                          (SELECT COUNT(*) FROM feedback f WHERE f.site_id = s.id) AS feedback_count
                   FROM sites s WHERE s.owner_user_id = ?
                   ORDER BY datetime(s.created_at) DESC`;
      const res = await env.DB.prepare(sql).bind(owner.sub).all<{
        id: string; name?: string; owner_email?: string | null; owner_user_id?: string | null; cors_json?: string; created_at: string; verified_at?: string | null; feedback_count?: number;
      }>();
      const rows = (res.results as any[]) || [];
      return rows.map((r) => ({
        id: r.id,
        name: r.name,
        owner_email: r.owner_email ?? null,
        owner_user_id: r.owner_user_id ?? null,
        cors: r.cors_json ? JSON.parse(r.cors_json) : [],
        created_at: r.created_at,
        verified_at: r.verified_at ?? null,
        feedback_count: Number(r.feedback_count || 0),
      }));
    } catch {
      // fall back to email if column missing
    }
  }
  return byEmail(owner.email);
}

// Owner check preferring sub, fallback to email
function isOwnerOfSite(site: any, user: AuthUser): boolean {
  if (site && site.owner_user_id && user.sub && String(site.owner_user_id) === String(user.sub)) return true;
  if (site && site.owner_email && user.email && String(site.owner_email).toLowerCase() === String(user.email).toLowerCase()) return true;
  return false;
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

// ------------- Auth (Clerk JWT) -------------
type AuthUser = { sub: string; email?: string };

const JWKS_CACHE: Map<string, { fetchedAt: number; keys: JsonWebKey[] }> = new Map();

function b64urlToUint8(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  const base = s + '='.repeat(pad);
  const bin = atob(base);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function fetchJwks(jwksUrl: string): Promise<JsonWebKey[]> {
  const cached = JWKS_CACHE.get(jwksUrl);
  const now = Date.now();
  if (cached && now - cached.fetchedAt < 15 * 60 * 1000) return cached.keys;
  const resp = await fetch(jwksUrl, { headers: { 'cache-control': 'no-cache' } });
  if (!resp.ok) throw new Error('jwks_fetch_failed');
  const data = await resp.json<{ keys: JsonWebKey[] }>();
  JWKS_CACHE.set(jwksUrl, { fetchedAt: now, keys: data.keys || [] });
  return data.keys || [];
}

async function verifyClerkJWT(env: Env, token: string): Promise<AuthUser | undefined> {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) return undefined;
    const header = JSON.parse(new TextDecoder().decode(b64urlToUint8(h)));
    const payload = JSON.parse(new TextDecoder().decode(b64urlToUint8(p)));
    const sig = b64urlToUint8(s);

    const iss = env.CLERK_ISSUER || '';
    const jwksUrl = env.CLERK_JWKS_URL || '';
    const iss2 = env.CLERK_ISSUER_2 || '';
    const jwksUrl2 = env.CLERK_JWKS_URL_2 || '';
    const aud = env.CLERK_AUDIENCE;
    if (!iss || !jwksUrl) return undefined;
    // Only enforce audience when both sides present; allow tokens without aud
    if (aud && payload.aud && payload.aud !== aud) return undefined;
    if (typeof payload.exp === 'number' && Date.now() / 1000 > payload.exp) return undefined;

    // Helper to attempt verify against a given JWKS
    const attemptVerify = async (jwksUrlTry: string, issTry: string): Promise<boolean> => {
      if (!jwksUrlTry) return false;
      // if token has iss, ensure it matches this issuer start
      if (payload.iss && issTry && !String(payload.iss).startsWith(issTry)) return false;
      const keys = await fetchJwks(jwksUrlTry);
      if (!keys || keys.length === 0) return false;
      const candidates = header.kid ? [
        ...keys.filter((k: any) => k.kid === header.kid),
        ...keys.filter((k: any) => k.kid !== header.kid),
      ] : keys;
      for (const jwk of candidates) {
        try {
          const cryptoKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
          if (await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sig, data)) return true;
        } catch {}
      }
      return false;
    };

    const algo = (header.alg as string) || 'RS256';
    if (!/^RS(256|384|512)$/.test(algo)) return undefined;
    const data = new TextEncoder().encode(`${h}.${p}`);

    // Try verification against all available JWKS keys if kid doesn't match
    let verified = await attemptVerify(jwksUrl, iss);
    if (!verified && jwksUrl2) {
      verified = await attemptVerify(jwksUrl2, iss2 || '');
    }
    if (!verified) return undefined;

    // Try multiple Clerk payload shapes for email
    const email: string | undefined =
      payload.email ||
      (payload as any)['email_address'] ||
      (payload as any)['primary_email_address'] ||
      (Array.isArray((payload as any).email_addresses) && (payload as any).email_addresses[0]?.email_address) ||
      ((payload as any).user && (((payload as any).user.email) || ((payload as any).user.email_address)));
    const sub: string | undefined = (payload as any).sub;
    if (!sub) return undefined;
    return { sub, email };
  } catch {
    return undefined;
  }
}

async function getAuth(env: Env, request: Request): Promise<AuthUser | undefined> {
  const auth = request.headers.get('authorization') || request.headers.get('Authorization');
  if (!auth || !auth.toLowerCase().startsWith('bearer ')) return undefined;
  const token = auth.slice(7).trim();
  return verifyClerkJWT(env, token);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { origin, isPreflight } = cors(request);

    if (isPreflight) {
      const h = new Headers({
        'access-control-allow-origin': origin || '*',
        'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
        // Allow Authorization for authenticated dashboard requests
        'access-control-allow-headers': 'content-type,authorization,x-fidbak-signature',
        // Cache preflight for 10 minutes to avoid repeated OPTIONS
        'access-control-max-age': '600',
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
        ).catch((e) => {
          try { console.warn('fidbak: fanout fatal', row.site_id, row.id, (e as any)?.message || e); } catch {}
        }),
      );
      return json({ accepted: true, id: row.id }, { status: 202 }, allow);
    }

    // GET /v1/sites  (list sites)
    if (url.pathname === '/v1/sites' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const ownerEmailQuery = (url.searchParams.get('ownerEmail') || '').trim();
      const authUser = await getAuth(env, request).catch(() => undefined);
      const ownerEmail = (authUser?.email || '').trim() || ownerEmailQuery;
      try {
        const sites = await listSitesByOwner(env, { sub: authUser?.sub, email: ownerEmail || undefined });
        return json({ sites }, {}, reqOrigin || '*');
      } catch (e) {
        return bad('list_failed', reqOrigin || '*');
      }
    }

    // DELETE /v1/sites/:id (owner-only; alias for deletion)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)$/);
      if (m && request.method === 'DELETE') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const siteForAuth = await getSiteFull(env, siteId);
        if (!siteForAuth) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(siteForAuth, authUser)) {
          return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        }
        try {
          await deleteSite(env, siteId);
          return json({ ok: true, siteId }, { status: 200 }, reqOrigin || '*');
        } catch {
          return bad('delete_failed', reqOrigin || '*');
        }
      }
    }

    // POST /v1/sites  (self-serve create)
    if (url.pathname === '/v1/sites' && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      let body: any = {};
      try {
        body = await request.json();
      } catch {}
      const id = (body?.id || '').trim();
      const name = (body?.name || '').trim() || id;
      // Fallback to client-provided ownerEmail only if token lacks email
      const owner_email = ((authUser.email || body?.ownerEmail || '') as string).trim().toLowerCase();
      // Require some owner email for now until we add owner_user_id storage
      if (!owner_email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(owner_email)) {
        return bad('owner_email_required', reqOrigin || '*');
      }
      const originToAllow = (body?.origin || '').trim();
      const moreOrigins = Array.isArray(body?.origins) ? body.origins.filter((o: any) => typeof o === 'string' && /^https?:\/\//.test(o)).map((s: string) => s.trim()) : [];
      if (!id || !/^[a-z0-9-]{3,}$/.test(id)) return bad('invalid_site_id', reqOrigin || '*');
      if (!originToAllow || !/^https?:\/\//.test(originToAllow)) return bad('invalid_origin', reqOrigin || '*');

      const verify_token = crypto.randomUUID();
      const dashboardOrigin = env.FIDBAK_DASH_ORIGIN || 'https://fidbak-dash.pages.dev';
      const set = new Set<string>([originToAllow, ...moreOrigins, dashboardOrigin]);
      const corsArr = Array.from(set);
      try {
        await upsertSite(env, { id, name, owner_email, owner_user_id: authUser.sub, cors: corsArr, verify_token });
        // Optional initial webhook
        if (body?.webhook && typeof body.webhook === 'object') {
          const wu = String(body.webhook.url || '').trim();
          const ws = typeof body.webhook.secret === 'string' ? body.webhook.secret : undefined;
          const active = body.webhook.active !== false;
          if (/^https?:\/\//.test(wu)) {
            await createSiteWebhook(env, id, { url: wu, secret: ws, active });
          }
        }
        const dashboard = env.FIDBAK_DASHBOARD_BASE
          ? `${env.FIDBAK_DASHBOARD_BASE}/?siteId=${encodeURIComponent(id)}`
          : undefined;
        return json(
          { ok: true, siteId: id, dashboard, cors: corsArr, verifyToken: verify_token },
          { status: 201 },
          reqOrigin || '*',
        );
      } catch {
        return bad('create_failed', reqOrigin || '*');
      }
    }

    // POST /v1/sites/:id/origins  (add/remove origins)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/origins$/);
      if (m && request.method === 'POST') {
        const { origin: reqOrigin } = cors(request);
        const siteId = decodeURIComponent(m[1] || '');
        // Authorization: only owner can mutate origins
        const authUser = await getAuth(env, request);
        if (!authUser?.email) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const siteForAuth = await getSiteFull(env, siteId);
        if (!siteForAuth) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(siteForAuth, authUser)) {
          return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        }
        let body: any = {};
        try {
          body = await request.json();
        } catch {}
        const add: string[] = Array.isArray(body?.add) ? body.add : [];
        const remove: string[] = Array.isArray(body?.remove) ? body.remove : [];
        const site = await getSite(env, siteId);
        const existing = new Set<string>((site?.cors || []).map(String));
        for (const a of add) if (/^https?:\/\//.test(a)) existing.add(a);
        for (const r of remove) existing.delete(r);
        const updated = Array.from(existing);
        try {
          await updateSiteCors(env, siteId, updated);
          return json({ ok: true, siteId, cors: updated }, { status: 200 }, reqOrigin || '*');
        } catch {
          return bad('update_failed', reqOrigin || '*');
        }
      }
    }

    // POST /v1/sites/:id/delete (owner-only; deletes site, feedback, webhooks)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/delete$/);
      if (m && request.method === 'POST') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const siteForAuth = await getSiteFull(env, siteId);
        if (!siteForAuth) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(siteForAuth, authUser)) {
          return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        }
        try {
          await deleteSite(env, siteId);
          return json({ ok: true, siteId }, { status: 200 }, reqOrigin || '*');
        } catch {
          return bad('delete_failed', reqOrigin || '*');
        }
      }
    }

    // GET /v1/sites/:id  (site details) - require owner auth
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)$/);
      if (m && request.method === 'GET') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const site = await getSiteFull(env, siteId);
        if (!site) return notFound(reqOrigin || '*');
        const isOwner = isOwnerOfSite(site, authUser);
        if (!isOwner) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        return json(site, {}, reqOrigin || '*');
      }
    }

    // GET /v1/sites/:id/feedback (owner-only)
    const match = url.pathname.match(/^\/v1\/sites\/([^/]+)\/feedback$/);
    if (match && request.method === 'GET') {
      const siteId = decodeURIComponent(match[1] || '');
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      const siteForAuth = await getSiteFull(env, siteId);
      if (!siteForAuth) return notFound(reqOrigin || '*');
      if (!isOwnerOfSite(siteForAuth, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      const allow = reqOrigin || '*';
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

    // GET /v1/sites/:id/summary?days=7 (owner-only)
    const matchSummary = url.pathname.match(/^\/v1\/sites\/([^/]+)\/summary$/);
    if (matchSummary && request.method === 'GET') {
      const siteId = decodeURIComponent(matchSummary[1] || '');
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      const siteForAuth = await getSiteFull(env, siteId);
      if (!siteForAuth) return notFound(reqOrigin || '*');
      if (!isOwnerOfSite(siteForAuth, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      const allow = reqOrigin || '*';
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

    // GET /v1/sites/:id/stats?days=7 (owner-only)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/stats$/);
      if (m && request.method === 'GET') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const siteForAuth = await getSiteFull(env, siteId);
        if (!siteForAuth) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(siteForAuth, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const allow = reqOrigin || '*';
        const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get('days') || '7', 10)));
        const stats = await computeSiteStats(env, siteId, days);
        if (!stats) return notFound(allow);
        return json(stats, {}, allow);
      }
    }

    // Webhook management endpoints (owner-only)
    // GET /v1/sites/:id/webhooks
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/webhooks$/);
      if (m && request.method === 'GET') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const site = await getSiteFull(env, siteId);
        if (!site) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(site, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const hooks = await listSiteWebhooks(env, siteId);
        return json({ webhooks: hooks }, {}, reqOrigin || '*');
      }
    }

    // POST /v1/sites/:id/webhooks (create)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/webhooks$/);
      if (m && request.method === 'POST') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const site = await getSiteFull(env, siteId);
        if (!site) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(site, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        let body: any = {};
        try { body = await request.json(); } catch {}
        const urlStr = String(body?.url || '').trim();
        const secret = typeof body?.secret === 'string' ? body.secret : undefined;
        const active = body?.active !== false;
        if (!/^https?:\/\//.test(urlStr)) return bad('invalid_url', reqOrigin || '*');
        const hook = await createSiteWebhook(env, siteId, { url: urlStr, secret, active });
        return json({ ok: true, webhook: hook }, { status: 201 }, reqOrigin || '*');
      }
    }

    // POST /v1/sites/:id/webhooks/:wid (update)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/webhooks\/([^/]+)$/);
      if (m && request.method === 'POST') {
        const siteId = decodeURIComponent(m[1] || '');
        const wid = decodeURIComponent(m[2] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const site = await getSiteFull(env, siteId);
        if (!site) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(site, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        let body: any = {};
        try { body = await request.json(); } catch {}
        const patch: any = {};
        if (typeof body.url === 'string') {
          const u = body.url.trim();
          if (!/^https?:\/\//.test(u)) return bad('invalid_url', reqOrigin || '*');
          patch.url = u;
        }
        if (typeof body.secret === 'string') patch.secret = body.secret;
        if (typeof body.active === 'boolean') patch.active = body.active;
        const updated = await updateSiteWebhook(env, siteId, wid, patch);
        if (!updated) return notFound(reqOrigin || '*');
        return json({ ok: true, webhook: updated }, {}, reqOrigin || '*');
      }
    }

    // POST /v1/sites/:id/webhooks/:wid/delete (soft delete -> deactivate)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/webhooks\/([^/]+)\/delete$/);
      if (m && request.method === 'POST') {
        const siteId = decodeURIComponent(m[1] || '');
        const wid = decodeURIComponent(m[2] || '');
        const { origin: reqOrigin } = cors(request);
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const site = await getSiteFull(env, siteId);
        if (!site) return notFound(reqOrigin || '*');
        if (!isOwnerOfSite(site, authUser)) return new Response('Forbidden', { status: 403, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        const updated = await updateSiteWebhook(env, siteId, wid, { active: false });
        if (!updated) return notFound(reqOrigin || '*');
        return json({ ok: true, webhook: updated }, {}, reqOrigin || '*');
      }
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

// Full site for dashboard
async function getSiteFull(
  env: Env,
  siteId: string,
): Promise<
  { id: string; name: string; owner_email?: string | null; owner_user_id?: string | null; cors: string[]; created_at?: string; verified_at?: string | null } | undefined
> {
  if (env.DB) {
    try {
      // Try with owner_user_id (new column)
      const row = await env.DB
        .prepare('SELECT id, name, owner_email, owner_user_id, cors_json, created_at, verified_at FROM sites WHERE id = ?')
        .bind(siteId)
        .first<{
          id: string;
          name: string;
          owner_email?: string | null;
          owner_user_id?: string | null;
          cors_json?: string;
          created_at?: string;
          verified_at?: string | null;
        }>();
      if (row)
        return {
          id: row.id,
          name: row.name,
          owner_email: row.owner_email ?? null,
          owner_user_id: row.owner_user_id ?? null,
          cors: row.cors_json ? JSON.parse(row.cors_json) : [],
          created_at: row.created_at,
          verified_at: row.verified_at ?? null,
        };
    } catch {}
    // Fallback query if column doesn't exist
    try {
      const row = await env.DB
        .prepare('SELECT id, name, owner_email, cors_json, created_at, verified_at FROM sites WHERE id = ?')
        .bind(siteId)
        .first<{
          id: string;
          name: string;
          owner_email?: string | null;
          cors_json?: string;
          created_at?: string;
          verified_at?: string | null;
        }>();
      if (row)
        return {
          id: row.id,
          name: row.name,
          owner_email: row.owner_email ?? null,
          owner_user_id: null,
          cors: row.cors_json ? JSON.parse(row.cors_json) : [],
          created_at: row.created_at,
          verified_at: row.verified_at ?? null,
        };
    } catch {}
  }
  const m = SITES[siteId];
  if (!m) return undefined;
  return { id: siteId, name: m.name, owner_email: null, owner_user_id: null, cors: m.cors || [], created_at: undefined, verified_at: null };
}

async function upsertSite(
  env: Env,
  data: { id: string; name: string; owner_email?: string | null; owner_user_id?: string | null; cors: string[]; verify_token?: string },
) {
  if (env.DB) {
    const cors_json = JSON.stringify(data.cors || []);
    // Try including owner_user_id (new column). Fallback to legacy insert on error.
    try {
      await env.DB
        .prepare(
          `INSERT INTO sites (id, name, owner_email, owner_user_id, cors_json, created_at, verify_token)
           VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)
           ON CONFLICT(id) DO UPDATE SET name=excluded.name, owner_email=excluded.owner_email, owner_user_id=excluded.owner_user_id, cors_json=excluded.cors_json`,
        )
        .bind(data.id, data.name, data.owner_email || null, data.owner_user_id || null, cors_json, data.verify_token || null)
        .run();
    } catch {
      await env.DB
        .prepare(
          `INSERT INTO sites (id, name, owner_email, cors_json, created_at, verify_token)
           VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)
           ON CONFLICT(id) DO UPDATE SET name=excluded.name, owner_email=excluded.owner_email, cors_json=excluded.cors_json`,
        )
        .bind(data.id, data.name, data.owner_email || null, cors_json, data.verify_token || null)
        .run();
    }
    return;
  }
  // memory fallback
  SITES[data.id] = { name: data.name, cors: data.cors };
}

async function updateSiteCors(env: Env, siteId: string, cors: string[]) {
  if (env.DB) {
    await env.DB.prepare('UPDATE sites SET cors_json = ? WHERE id = ?').bind(JSON.stringify(cors || []), siteId).run();
    return;
  }
  if (SITES[siteId]) SITES[siteId].cors = cors;
}

// Hard delete a site and related rows
async function deleteSite(env: Env, siteId: string) {
  if (env.DB) {
    // Order: feedback -> webhooks -> site
    await env.DB.prepare('DELETE FROM feedback WHERE site_id = ?').bind(siteId).run();
    try { await env.DB.prepare('DELETE FROM site_webhooks WHERE site_id = ?').bind(siteId).run(); } catch {}
    await env.DB.prepare('DELETE FROM sites WHERE id = ?').bind(siteId).run();
    return;
  }
  // memory fallback
  try { delete SITES[siteId]; } catch {}
  try { MEM.feedback = MEM.feedback.filter((f) => f.site_id !== siteId); } catch {}
}

// List sites with basic metadata and feedback_count
async function listSites(
  env: Env,
  ownerEmail?: string,
): Promise<Array<{
  id: string;
  name?: string;
  owner_email?: string | null;
  cors: string[];
  created_at: string;
  verified_at?: string | null;
  feedback_count?: number;
}>> {
  if (env.DB) {
    try {
      const where = ownerEmail ? 'WHERE s.owner_email = ?' : '';
      const sql = `SELECT s.id, s.name, s.owner_email, s.cors_json, s.created_at, s.verified_at,
                          (SELECT COUNT(*) FROM feedback f WHERE f.site_id = s.id) AS feedback_count
                   FROM sites s ${where}
                   ORDER BY datetime(s.created_at) DESC`;
      const stmt = env.DB.prepare(sql);
      const res = ownerEmail
        ? await stmt.bind(ownerEmail).all<{
            id: string;
            name?: string;
            owner_email?: string | null;
            cors_json?: string;
            created_at: string;
            verified_at?: string | null;
            feedback_count?: number;
          }>()
        : await stmt.all<{
            id: string;
            name?: string;
            owner_email?: string | null;
            cors_json?: string;
            created_at: string;
            verified_at?: string | null;
            feedback_count?: number;
          }>();
      const rows = (res.results as any[]) || [];
      return rows.map((r) => ({
        id: r.id,
        name: r.name,
        owner_email: r.owner_email ?? null,
        cors: r.cors_json ? JSON.parse(r.cors_json) : [],
        created_at: r.created_at,
        verified_at: r.verified_at ?? null,
        feedback_count: Number(r.feedback_count || 0),
      }));
    } catch {
      // fall through to memory
    }
  }
  // Memory fallback
  const entries = Object.entries(SITES);
  const filtered = ownerEmail ? [] : entries; // memory store has no owner tracking
  return filtered.map(([id, m]) => ({
    id,
    name: m.name,
    owner_email: null,
    cors: m.cors || [],
    created_at: new Date().toISOString(),
    verified_at: null,
    feedback_count: MEM.feedback.filter((f) => f.site_id === id).length,
  }));
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
  const all: string[] = Array.isArray(destinations) ? [...destinations] : [];
  const redact = (u: string) => u.replace(/(https:\/\/hooks\.slack\.com\/services\/)[^/]+\/[^/]+\/.+/, '$1***');
  // Load site-managed webhooks
  try {
    const hooks = await listSiteWebhooks(env, row.site_id);
    for (const h of hooks) {
      if (h.active && /^https?:\/\//.test(h.url)) all.push(h.url);
    }
    try { console.log('fidbak: fanout targets', row.site_id, row.id, { provided: (destinations||[]).length, stored: hooks.length, total: all.length }); } catch {}
  } catch (e) {
    try { console.warn('fidbak: listSiteWebhooks failed', row.site_id, (e as any)?.message || e); } catch {}
  }

  if (all.length === 0) {
    try { console.log('fidbak: fanout skipped (no destinations)', row.site_id, row.id); } catch {}
    return;
  }

  await Promise.all(
    all.map(async (url) => {
      const redacted = redact(url);
      try {
        const isSlack = /^https:\/\/hooks\.slack\.com\//.test(url);
        let bodyStr = '';
        const headers: Record<string, string> = { 'content-type': 'application/json' };

        if (isSlack) {
          const blocks = makeSlackBlocks(env, row);
          bodyStr = JSON.stringify({ text: row.comment || `${row.rating.toUpperCase()} feedback on ${row.page_id}`, blocks });
          try { console.log('fidbak: webhook -> Slack', row.site_id, row.id, redacted); } catch {}
        } else {
          bodyStr = JSON.stringify({ type: 'fidbak.feedback.v1', data: row });
          let secretToUse: string | undefined = webhookSecret;
          try {
            const hook = await getSiteWebhookByUrl(env, row.site_id, url);
            if (hook?.secret) secretToUse = hook.secret;
          } catch {}
          if (secretToUse) headers['x-fidbak-signature'] = await hmacSHA256Hex(secretToUse, bodyStr);
          try { console.log('fidbak: webhook -> Generic', row.site_id, row.id, new URL(url).hostname); } catch {}
        }

        const resp = await fetch(url, { method: 'POST', headers, body: bodyStr });
        if (!resp.ok) {
          console.warn('fidbak: webhook non-2xx', redacted, resp.status);
          try { console.warn('fidbak: webhook resp', await resp.text()); } catch {}
        } else {
          try { console.log('fidbak: webhook delivered', redacted, resp.status); } catch {}
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
  // Deprecated: Slack-specific helper retained for backward compatibility only.
  // No-op; use generic JSON webhooks per site instead.
}

// ---------- site webhook storage ----------
type SiteWebhook = { id: string; site_id: string; url: string; secret?: string | null; active: number; created_at: string };

async function listSiteWebhooks(env: Env, siteId: string): Promise<Array<{ id: string; url: string; secret?: string | null; active: boolean; created_at: string }>> {
  if (!env.DB) return [];
  try {
    const res = await env.DB
      .prepare('SELECT id, site_id, url, secret, active, created_at FROM site_webhooks WHERE site_id = ? ORDER BY datetime(created_at) DESC')
      .bind(siteId)
      .all<SiteWebhook>();
    const rows = (res.results as any[]) || [];
    return rows.map((r) => ({ id: r.id, url: r.url, secret: r.secret ?? null, active: Number(r.active) === 1, created_at: r.created_at }));
  } catch {
    return [];
  }
}

async function getSiteWebhookByUrl(env: Env, siteId: string, url: string): Promise<{ id: string; url: string; secret?: string | null; active: boolean } | undefined> {
  if (!env.DB) return undefined;
  try {
    const row = await env.DB
      .prepare('SELECT id, url, secret, active FROM site_webhooks WHERE site_id = ? AND url = ? LIMIT 1')
      .bind(siteId, url)
      .first<{ id: string; url: string; secret?: string | null; active: number }>();
    if (!row) return undefined;
    return { id: row.id, url: row.url, secret: row.secret ?? null, active: Number(row.active) === 1 };
  } catch {
    return undefined;
  }
}

async function createSiteWebhook(env: Env, siteId: string, data: { url: string; secret?: string; active?: boolean }) {
  if (!env.DB) return { id: crypto.randomUUID(), url: data.url, secret: data.secret ?? null, active: !!data.active, created_at: new Date().toISOString() };
  const id = crypto.randomUUID();
  const active = data.active !== false;
  await env.DB
    .prepare('INSERT INTO site_webhooks (id, site_id, url, secret, active, created_at) VALUES (?, ?, ?, ?, ?, strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))')
    .bind(id, siteId, data.url, data.secret || null, active ? 1 : 0)
    .run();
  return { id, url: data.url, secret: data.secret ?? null, active, created_at: new Date().toISOString() };
}

async function updateSiteWebhook(env: Env, siteId: string, id: string, patch: { url?: string; secret?: string; active?: boolean }) {
  if (!env.DB) return { id, url: patch.url || '', secret: patch.secret ?? null, active: !!patch.active, created_at: new Date().toISOString() };
  // Build dynamic update
  const sets: string[] = [];
  const binds: any[] = [];
  if (typeof patch.url === 'string') { sets.push('url = ?'); binds.push(patch.url); }
  if (typeof patch.secret === 'string') { sets.push('secret = ?'); binds.push(patch.secret); }
  if (typeof patch.active === 'boolean') { sets.push('active = ?'); binds.push(patch.active ? 1 : 0); }
  if (sets.length === 0) return undefined;
  binds.push(siteId, id);
  const sql = `UPDATE site_webhooks SET ${sets.join(', ')} WHERE site_id = ? AND id = ?`;
  const res = await env.DB.prepare(sql).bind(...binds).run();
  if ((res as any)?.success === false) return undefined;
  // Return updated
  const row = await env.DB.prepare('SELECT id, url, secret, active, created_at FROM site_webhooks WHERE site_id = ? AND id = ?').bind(siteId, id).first<{ id: string; url: string; secret?: string | null; active: number; created_at: string }>();
  if (!row) return undefined;
  return { id: row.id, url: row.url, secret: row.secret ?? null, active: Number(row.active) === 1, created_at: row.created_at };
}

// ---------- analytics helpers ----------
async function computeSiteStats(
  env: Env,
  siteId: string,
  days: number,
): Promise<{
  totals: { all: number; up: number; down: number; satisfactionPct: number };
  lastN: { days: number; up: number; down: number; total: number; satisfactionPct: number };
  prevN: { days: number; up: number; down: number; total: number; satisfactionPct: number };
  deltas: { totalPct: number; satisfactionPct: number };
} | undefined> {
  const now = Date.now();
  const winMs = days * 24 * 60 * 60 * 1000;
  const sinceIso = new Date(now - winMs).toISOString();
  const prevSinceIso = new Date(now - 2 * winMs).toISOString();
  if (env.DB) {
    try {
      const totalRow = await env.DB
        .prepare("SELECT COUNT(*) AS c, SUM(CASE WHEN rating='up' THEN 1 ELSE 0 END) AS up, SUM(CASE WHEN rating='down' THEN 1 ELSE 0 END) AS down FROM feedback WHERE site_id = ?")
        .bind(siteId)
        .first<{ c: number; up: number; down: number }>();
      const lastRow = await env.DB
        .prepare("SELECT SUM(CASE WHEN rating='up' THEN 1 ELSE 0 END) AS up, SUM(CASE WHEN rating='down' THEN 1 ELSE 0 END) AS down FROM feedback WHERE site_id = ? AND datetime(created_at) >= datetime(?)")
        .bind(siteId, sinceIso)
        .first<{ up: number; down: number }>();
      const prevRow = await env.DB
        .prepare("SELECT SUM(CASE WHEN rating='up' THEN 1 ELSE 0 END) AS up, SUM(CASE WHEN rating='down' THEN 1 ELSE 0 END) AS down FROM feedback WHERE site_id = ? AND datetime(created_at) < datetime(?) AND datetime(created_at) >= datetime(?)")
        .bind(siteId, sinceIso, prevSinceIso)
        .first<{ up: number; down: number }>();

      const all = Number(totalRow?.c || 0);
      const upAll = Number(totalRow?.up || 0);
      const downAll = Number(totalRow?.down || 0);
      const satAll = all > 0 ? (upAll / (upAll + downAll)) * 100 : 0;

      const lastUp = Number(lastRow?.up || 0);
      const lastDown = Number(lastRow?.down || 0);
      const lastTotal = lastUp + lastDown;
      const lastSat = lastTotal > 0 ? (lastUp / lastTotal) * 100 : 0;

      const prevUp = Number(prevRow?.up || 0);
      const prevDown = Number(prevRow?.down || 0);
      const prevTotal = prevUp + prevDown;
      const prevSat = prevTotal > 0 ? (prevUp / prevTotal) * 100 : 0;

      const totalPct = prevTotal > 0 ? ((lastTotal - prevTotal) / prevTotal) * 100 : (lastTotal > 0 ? 100 : 0);
      const satPct = prevTotal > 0 ? (lastSat - prevSat) : lastSat;

      return {
        totals: { all, up: upAll, down: downAll, satisfactionPct: round2(satAll) },
        lastN: { days, up: lastUp, down: lastDown, total: lastTotal, satisfactionPct: round2(lastSat) },
        prevN: { days, up: prevUp, down: prevDown, total: prevTotal, satisfactionPct: round2(prevSat) },
        deltas: { totalPct: round2(totalPct), satisfactionPct: round2(satPct) },
      };
    } catch {
      // fall through to memory
    }
  }
  // memory fallback
  const allRows = MEM.feedback.filter((f) => f.site_id === siteId);
  const all = allRows.length;
  const upAll = allRows.filter((f) => f.rating === 'up').length;
  const downAll = allRows.filter((f) => f.rating === 'down').length;
  const satAll = all > 0 ? (upAll / (upAll + downAll)) * 100 : 0;

  const since = now - winMs;
  const prevSince = now - 2 * winMs;
  const lastRows = allRows.filter((f) => new Date(f.created_at).getTime() >= since);
  const prevRows = allRows.filter((f) => {
    const t = new Date(f.created_at).getTime();
    return t < since && t >= prevSince;
  });
  const lastUp = lastRows.filter((f) => f.rating === 'up').length;
  const lastDown = lastRows.filter((f) => f.rating === 'down').length;
  const lastTotal = lastRows.length;
  const lastSat = lastTotal > 0 ? (lastUp / lastTotal) * 100 : 0;
  const prevUp = prevRows.filter((f) => f.rating === 'up').length;
  const prevDown = prevRows.filter((f) => f.rating === 'down').length;
  const prevTotal = prevRows.length;
  const prevSat = prevTotal > 0 ? (prevUp / prevTotal) * 100 : 0;

  const totalPct = prevTotal > 0 ? ((lastTotal - prevTotal) / prevTotal) * 100 : (lastTotal > 0 ? 100 : 0);
  const satPct = prevTotal > 0 ? (lastSat - prevSat) : lastSat;

  return {
    totals: { all, up: upAll, down: downAll, satisfactionPct: round2(satAll) },
    lastN: { days, up: lastUp, down: lastDown, total: lastTotal, satisfactionPct: round2(lastSat) },
    prevN: { days, up: prevUp, down: prevDown, total: prevTotal, satisfactionPct: round2(prevSat) },
    deltas: { totalPct: round2(totalPct), satisfactionPct: round2(satPct) },
  };
}

function round2(n: number) {
  return Math.round(n * 100) / 100;
}
