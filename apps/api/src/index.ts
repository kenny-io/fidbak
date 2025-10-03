// Welcome email using provided template (inline for Worker)
function renderWelcomeHtml(firstName: string, ctaUrl: string, ctaText: string): string {
  const safe = firstName || 'there';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Welcome to Fidbak</title></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background-color:#f9fafb;"><table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f9fafb;padding:40px 20px;"><tr><td align="center"><table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);"><tr><td style="background:linear-gradient(135deg,#f97316 0%,#ea580c 100%);padding:40px 40px 30px;text-align:center;"><h1 style="margin:0;color:#ffffff;font-size:32px;font-weight:700;letter-spacing:-0.5px;">Fidbak</h1><p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">Lightweight customer feedback platform</p></td></tr><tr><td style="padding:40px;"><p style="margin:0 0 8px;color:#111827;font-size:16px;line-height:1.6;">Hi ${safe},</p><p style="margin:0 0 16px;color:#4b5563;font-size:16px;line-height:1.6;">I’m Kenny. Thanks for signing up for Fidbak.</p><p style="margin:0 0 16px;color:#4b5563;font-size:16px;line-height:1.6;">I started Fidbak to make feedback simple and useful so you can make better, user driven decisions for your product and business.</p><p style="margin:0 0 24px;color:#4b5563;font-size:16px;line-height:1.6;">Whether you are just exploring or ready to collect feedback on your site, I am glad you are here.</p><table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;"><tr><td style="background-color:#fef3c7;padding:20px;border-radius:8px;border-left:4px solid #f97316;"><p style="margin:0;color:#78350f;font-size:14px;line-height:1.5;">If you have any questions or need help with integrating Fidbak into your site, hit reply and I will get back to you. I read and answer every message myself.</p></td></tr></table>
  <div style="text-align:center;margin:24px 0;">
    <a href="${ctaUrl}" style="display:inline-block;background-color:#f97316;color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:600;">
      ${ctaText}
    </a>
  </div>
  <p style="margin:0 0 4px;color:#4b5563;font-size:16px;line-height:1.6;">Glad to have you with us.</p><br><p style="margin:0;color:#111827;font-size:16px;line-height:1.6;"><strong>Kenny</strong><br><span style="color:#6b7280;font-size:14px;">Founder, Fidbak</span></p></td></tr><tr><td style="padding:24px 40px;background-color:#f9fafb;border-top:1px solid #e5e7eb;"><p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;line-height:1.5;">© 2025 Fidbak. All rights reserved.<br>You're receiving this because you created a Fidbak account.</p></td></tr></table></td></tr></table></body></html>`;
}

// ---------- plan features helpers ----------
async function getPlanFeatures(env: Env, planId: string | null | undefined): Promise<any> {
  const pid = (planId || 'free').toString();
  if (!env.DB) return defaultFeatures(pid);
  try {
    const row = await env.DB
      .prepare('SELECT features_json FROM plans WHERE id = ? LIMIT 1')
      .bind(pid)
      .first<{ features_json?: string | null }>();
    if (row?.features_json) {
      try { return JSON.parse(row.features_json); } catch {}
    }
  } catch {}
  return defaultFeatures(pid);
}

function defaultFeatures(planId: string): any {
  // Sensible defaults if plans table missing
  if (planId === 'team') return { sites: 10, seats: 5 };
  if (planId === 'pro') return { sites: 3, seats: 1 };
  if (planId === 'enterprise') return { sites: 50, seats: 25 };
  return { sites: 1, seats: 1 }; // free
}

// ---- Org role helpers ----
async function getOrgRole(env: Env, orgId: string, user: AuthUser): Promise<{ role: string | null; status: string | null; is_owner: boolean; is_admin: boolean }> {
  if (!env.DB) return { role: null, status: null, is_owner: false, is_admin: false };
  // Owner by sub
  try {
    const owner = await env.DB.prepare('SELECT 1 FROM orgs WHERE id = ? AND owner_sub = ? LIMIT 1').bind(orgId, user.sub).first<any>();
    if (owner) return { role: 'owner', status: 'active', is_owner: true, is_admin: true };
  } catch {}
  // Member by user_sub
  try {
    const m = await env.DB
      .prepare('SELECT role, status FROM org_members WHERE org_id = ? AND user_sub = ? LIMIT 1')
      .bind(orgId, user.sub)
      .first<{ role: string; status: string }>();
    const role = m?.role || null;
    const status = m?.status || null;
    const is_admin = !!(status === 'active' && (role === 'owner' || role === 'admin'));
    return { role, status, is_owner: false, is_admin };
  } catch {}
  return { role: null, status: null, is_owner: false, is_admin: false };
}

async function ensureOrgAdmin(env: Env, orgId: string, user: AuthUser): Promise<boolean> {
  const r = await getOrgRole(env, orgId, user);
  return r.is_admin;
}

// New: Team invite email template (styled like welcome)
function renderInviteHtml(inviterName: string, orgName: string, acceptUrl: string): string {
  const inviter = inviterName || 'A teammate';
  const org = orgName || 'your team';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>You're invited to Fidbak</title></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background-color:#f9fafb;"><table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f9fafb;padding:40px 20px;"><tr><td align="center"><table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);"><tr><td style="background:linear-gradient(135deg,#f97316 0%,#ea580c 100%);padding:40px 40px 30px;text-align:center;"><h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:700;letter-spacing:-0.3px;">You're invited to Fidbak</h1><p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">Lightweight customer feedback platform</p></td></tr><tr><td style="padding:40px;"><p style="margin:0 0 16px;color:#111827;font-size:16px;line-height:1.6;">Hey there,</p><p style="margin:0 0 16px;color:#4b5563;font-size:16px;line-height:1.6;"><strong>${inviter}</strong> has invited you to join <strong>${org}</strong> on Fidbak.</p><div style="text-align:center;margin:24px 0;"><a href="${acceptUrl}" style="display:inline-block;background-color:#f97316;color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:8px;font-weight:600;">Accept invite</a></div><p style="margin:0;color:#6b7280;font-size:13px;line-height:1.6;">If you didn’t expect this, you can ignore this email.</p></td></tr><tr><td style="padding:24px 40px;background-color:#f9fafb;border-top:1px solid #e5e7eb;"><p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;line-height:1.5;">© 2025 Fidbak. All rights reserved.</p></td></tr></table></td></tr></table></body></html>`;
}

async function sendWelcomeEmail(env: Env, to: string, firstName: string, ctaUrl: string, ctaText: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.INVITE_FROM_EMAIL) return;
  const subject = 'Welcome to Fidbak';
  const html = renderWelcomeHtml(firstName || 'there', ctaUrl, ctaText);
  const text = `Hi ${firstName || 'there'},\n\nThanks for signing up for Fidbak. Get started: ${ctaUrl}\n\nIf you have any questions, just reply to this email.\n\n— Kenny, Founder`;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.INVITE_FROM_EMAIL, to: [to], subject, html, text }),
  });
  try {
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      console.error('Resend welcome email failed', resp.status, body);
    }
  } catch {}
}
export interface Env {
  DB?: D1Database; // optional binding
  FIDBAK_DASHBOARD_BASE?: string; // used in Slack footer link
  // Deprecated: global webhook removed; use per-site managed webhooks instead
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
  // Dev-only: when '1', the worker will attempt to auto-create missing tables in local env
  FIDBAK_DEV_AUTOMIGRATE?: string;
  // Stripe (Phase 2)
  STRIPE_SECRET_KEY?: string; // sk_live_... or sk_test_...
  STRIPE_WEBHOOK_SECRET?: string; // whsec_...
  STRIPE_PRICE_PRO?: string; // price_...
  STRIPE_PRICE_TEAM?: string; // price_...
  STRIPE_PRICE_ENTERPRISE?: string; // optional
  STRIPE_PORTAL_RETURN_URL?: string; // where to send users back to dashboard
  // Quota enforcement flags
  FIDBAK_ENFORCE_QUOTAS?: string; // '1' to enable hard blocking
  FIDBAK_BILLING_GRACE_DAYS?: string; // e.g., '7'
  // Invites & email
  RESEND_API_KEY?: string; // for sending invite emails
  INVITE_FROM_EMAIL?: string; // from address
  DASH_BASE_URL?: string; // e.g. https://fidbak.dev
}

// ----- Invites helpers -----
async function generateInviteToken(): Promise<string> {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function buildAcceptUrl(env: Env, token: string): string {
  const base = (env.DASH_BASE_URL && env.DASH_BASE_URL.startsWith('http'))
    ? env.DASH_BASE_URL
    : `https://${env.DASH_BASE_URL || 'fidbak.dev'}`;
  const b = base.replace(/\/$/, '');
  return `${b}/accept-invite?token=${encodeURIComponent(token)}`;
}

async function sendInviteEmail(env: Env, to: string, orgName: string, acceptUrl: string, inviterName?: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.INVITE_FROM_EMAIL) return;
  const inviter = inviterName && inviterName.trim().length ? inviterName.trim() : orgName;
  const subject = `${inviter} invited you to join ${orgName} on Fidbak`;
  const html = renderInviteHtml(inviter, orgName, acceptUrl);
  const text = `You’ve been invited to join ${orgName} on Fidbak.\n\nAccept invite: ${acceptUrl}\n\nIf you didn’t expect this, you can ignore this email.`;
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: env.INVITE_FROM_EMAIL, to: [to], subject, html, text }),
  });
  // Best-effort: log failures for debugging in tail logs but do not throw
  try {
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      console.error('Resend invite email failed', resp.status, body);
    }
  } catch {}
}

// Shared helper: POST to Stripe and return JSON or throw with detailed error
async function stripePost(env: Env, url: string, body: URLSearchParams): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) {
    const msg = json?.error?.message || text || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return json;
}

// ---------- billing helpers (Phase 2: Stripe skeleton) ----------
function planToPrice(env: Env, planId: string): string | null {
  const p = (s?: string) => (s && s.trim().length > 0 ? s.trim() : null);
  if (planId === 'pro') return p(env.STRIPE_PRICE_PRO);
  if (planId === 'team') return p(env.STRIPE_PRICE_TEAM);
  if (planId === 'enterprise') return p(env.STRIPE_PRICE_ENTERPRISE);
  return p(env.STRIPE_PRICE_PRO);
}

function mapPriceToPlan(env: Env, priceId?: string): string | null {
  if (!priceId) return null;
  if (env.STRIPE_PRICE_PRO === priceId) return 'pro';
  if (env.STRIPE_PRICE_TEAM === priceId) return 'team';
  if (env.STRIPE_PRICE_ENTERPRISE === priceId) return 'enterprise';
  return null;
}

async function getOrCreateOrgForOwner(env: Env, owner: { sub?: string; email?: string }): Promise<{ org: any; created: boolean }> {
  if (!env.DB) throw new Error('DB not configured');
  const sub = owner.sub || null;
  const email = owner.email || null;
  // 1) Prefer an active membership org for this user
  if (sub) {
    try {
      const memberOrg = await env.DB
        .prepare(`SELECT o.*
                  FROM org_members m
                  JOIN orgs o ON o.id = m.org_id
                  WHERE m.user_sub = ? AND m.status = 'active'
                  ORDER BY datetime(COALESCE(m.joined_at, m.invited_at)) DESC
                  LIMIT 1`)
        .bind(sub)
        .first<any>();
      if (memberOrg) return { org: memberOrg, created: false } as any;
    } catch {}
  }
  // 2) Fallback to an org owned by this user (sub preferred, then email)
  let org = await env.DB.prepare('SELECT * FROM orgs WHERE owner_sub = ? LIMIT 1').bind(sub).first<any>();
  if (!org && email) {
    org = await env.DB.prepare('SELECT * FROM orgs WHERE owner_email = ? LIMIT 1').bind(email).first<any>();
  }
  if (org) return { org, created: false } as any;
  // 3) Create new org on-the-fly with Free plan (personal org)
  const id = crypto.randomUUID();
  const created = new Date().toISOString();
  await env.DB
    .prepare('INSERT INTO orgs (id, name, owner_sub, owner_email, plan_id, stripe_customer_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, email ? `${email.split('@')[0]}'s Org` : 'My Org', sub, email, 'free', null, created)
    .run();
  const createdOrg = await env.DB.prepare('SELECT * FROM orgs WHERE id = ?').bind(id).first<any>();
  return { org: createdOrg as any, created: true };
}

async function getOrCreateStripeCustomer(env: Env, org: any, authUser: { email?: string }) {
  if (org?.stripe_customer_id) return org.stripe_customer_id as string;
  if (!env.STRIPE_SECRET_KEY) throw new Error('Stripe not configured');
  const email = authUser?.email || org?.owner_email || undefined;
  const body = new URLSearchParams();
  if (email) body.set('email', email);
  body.set('metadata[org_id]', org.id);
  const json = await stripePost(env, 'https://api.stripe.com/v1/customers', body);
  if (!json?.id) throw new Error('stripe customers.create failed: missing id');
  const customerId = json.id as string;
  if (env.DB) {
    await env.DB.prepare('UPDATE orgs SET stripe_customer_id = ? WHERE id = ?').bind(customerId, org.id).run();
  }
  return customerId;
}

async function createStripeCheckoutSession(env: Env, args: { customer?: string; customer_email?: string; priceId: string; mode: 'subscription'; success_url: string; cancel_url: string }) {
  const body = new URLSearchParams();
  body.set('mode', args.mode);
  if (args.customer) body.set('customer', args.customer);
  if (args.customer_email) body.set('customer_email', args.customer_email);
  body.set('line_items[0][price]', args.priceId);
  body.set('line_items[0][quantity]', '1');
  body.set('success_url', args.success_url);
  body.set('cancel_url', args.cancel_url);
  const json = await stripePost(env, 'https://api.stripe.com/v1/checkout/sessions', body);
  return json;
}

async function createStripePortalSession(env: Env, customerId: string, returnUrl: string) {
  const body = new URLSearchParams();
  body.set('customer', customerId);
  body.set('return_url', returnUrl);
  const json = await stripePost(env, 'https://api.stripe.com/v1/billing_portal/sessions', body);
  return json;
}

async function handleStripeEvent(env: Env, event: any) {
  if (!env.DB) return;
  const type = String(event?.type || '');
  // Extract org_id when possible from metadata; otherwise resolve via customer lookup
  const data = event?.data?.object || {};
  if (type === 'checkout.session.completed') {
    const customer = data?.customer as string | undefined;
    const sub = data?.subscription || {};
    const priceId = sub?.items?.data?.[0]?.price?.id || data?.display_items?.[0]?.price?.id || undefined;
    const status = sub?.status || 'active';
    const current_period_end = sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : undefined;
    if (customer) {
      const org = await env.DB.prepare('SELECT * FROM orgs WHERE stripe_customer_id = ? LIMIT 1').bind(customer).first<any>();
      const plan = mapPriceToPlan(env, priceId) || 'pro';
      if (org) {
        await env.DB.prepare('UPDATE orgs SET plan_id = ?, price_id = ?, subscription_status = ?, current_period_end = ? WHERE id = ?')
          .bind(plan, priceId || null, status, current_period_end || null, org.id)
          .run();
      }
    }
  } else if (type === 'customer.subscription.updated' || type === 'customer.subscription.created') {
    const sub = data;
    const customer = sub?.customer as string | undefined;
    const priceId = sub?.items?.data?.[0]?.price?.id as string | undefined;
    const status = sub?.status || null;
    const current_period_end = sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
    const cancel_at = sub?.cancel_at ? new Date(sub.cancel_at * 1000).toISOString() : null;
    const trial_end = sub?.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
    if (customer) {
      const org = await env.DB.prepare('SELECT * FROM orgs WHERE stripe_customer_id = ? LIMIT 1').bind(customer).first<any>();
      const plan = mapPriceToPlan(env, priceId);
      if (org) {
        await env.DB.prepare('UPDATE orgs SET plan_id = COALESCE(?, plan_id), price_id = ?, subscription_status = ?, current_period_end = ?, cancel_at = ?, trial_end = ? WHERE id = ?')
          .bind(plan || null, priceId || null, status, current_period_end, cancel_at, trial_end, org.id)
          .run();
      }
    }
  } else if (type === 'customer.subscription.deleted') {
    const customer = data?.customer as string | undefined;
    if (customer) {
      const org = await env.DB.prepare('SELECT * FROM orgs WHERE stripe_customer_id = ? LIMIT 1').bind(customer).first<any>();
      if (org) await env.DB.prepare('UPDATE orgs SET plan_id = ?, subscription_status = ? WHERE id = ?').bind('free', 'canceled', org.id).run();
    }
  }
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
    // IMPORTANT: declare `data` before it is captured by attemptVerify()
    const data = new TextEncoder().encode(`${h}.${p}`);

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

    // Try verification against all available JWKS keys if kid doesn't match
    let verified = await attemptVerify(jwksUrl, iss);
    if (!verified && jwksUrl2) {
      verified = await attemptVerify(jwksUrl2, iss2 || '');
    }
    if (!verified) {
      // Dev fallback: in local env allow unverified tokens if issuer matches configured dev issuer and token not expired
      const isDev = env.FIDBAK_DEV_AUTOMIGRATE === '1';
      const issMatch = (payload.iss && ((iss && String(payload.iss).startsWith(iss)) || (iss2 && String(payload.iss).startsWith(iss2)))) || false;
      if (!(isDev && issMatch)) return undefined;
    }

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
        'access-control-allow-methods': 'GET,POST,PATCH,DELETE,OPTIONS',
        // Allow Authorization for authenticated dashboard requests
        'access-control-allow-headers': 'content-type,authorization,x-fidbak-signature',
        // Cache preflight for 10 minutes to avoid repeated OPTIONS
        'access-control-max-age': '600',
      });
      return new Response(null, { status: 204, headers: h });
    }

    // ---------- Phase 2: Billing (Stripe) ----------
    if (url.pathname === '/v1/billing/checkout' && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      try {
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        if (!env.STRIPE_SECRET_KEY) return json({ error: 'Billing not configured' }, { status: 501 }, reqOrigin || '*');

        let body: any = {};
        try { body = await request.json(); } catch {}
        const planId = String(body?.planId || 'pro');
        const priceId = planToPrice(env, planId);
        if (!priceId) return json({ error: 'Unsupported plan' }, { status: 400 }, reqOrigin || '*');

        const { org } = await getOrCreateOrgForOwner(env, authUser);
        let customerId = await getOrCreateStripeCustomer(env, org, authUser);
        try {
          const session = await createStripeCheckoutSession(env, {
            customer: customerId,
            priceId,
            mode: 'subscription',
            success_url: (env.FIDBAK_DASHBOARD_BASE || reqOrigin || '') + '/billing?success=1',
            cancel_url: (env.FIDBAK_DASHBOARD_BASE || reqOrigin || '') + '/billing?canceled=1',
          });
          return json({ url: session?.url || null }, {}, reqOrigin || '*');
        } catch (e: any) {
          const msg = String(e?.message || e || '');
          if (msg.includes('No such customer')) {
            // Stale customer from another Stripe env/account; reset and retry once
            if (env.DB) {
              await env.DB.prepare('UPDATE orgs SET stripe_customer_id = NULL WHERE id = ?').bind(org.id).run();
            }
            customerId = await getOrCreateStripeCustomer(env, { ...org, stripe_customer_id: null }, authUser);
            const session = await createStripeCheckoutSession(env, {
              customer: customerId,
              priceId,
              mode: 'subscription',
              success_url: (env.FIDBAK_DASHBOARD_BASE || reqOrigin || '') + '/billing?success=1',
              cancel_url: (env.FIDBAK_DASHBOARD_BASE || reqOrigin || '') + '/billing?canceled=1',
            });
            return json({ url: session?.url || null }, {}, reqOrigin || '*');
          }
          throw e;
        }
      } catch (e: any) {
        return json({ error: String(e?.message || e || 'Unknown error') }, { status: 500 }, reqOrigin || '*');
      }
    }

    if (url.pathname === '/v1/billing/portal' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      try {
        const authUser = await getAuth(env, request);
        if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
        if (!env.STRIPE_SECRET_KEY) return json({ error: 'Billing not configured' }, { status: 501 }, reqOrigin || '*');

        const { org } = await getOrCreateOrgForOwner(env, authUser);
        const customerId = await getOrCreateStripeCustomer(env, org, authUser);
        const session = await createStripePortalSession(env, customerId, env.STRIPE_PORTAL_RETURN_URL || (env.FIDBAK_DASHBOARD_BASE || reqOrigin || '')); 
        return json({ url: session?.url || null }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e || 'Unknown error') }, { status: 500 }, reqOrigin || '*');
      }
    }

    if (url.pathname === '/v1/billing/webhook' && request.method === 'POST') {
      // Stripe webhook signature verification using existing HMAC helper
      const sigHeader = request.headers.get('stripe-signature') || '';
      const raw = await request.text();
      if (!env.STRIPE_WEBHOOK_SECRET || !env.STRIPE_SECRET_KEY) {
        // Not configured; acknowledge to avoid retries in dev
        return new Response('ok', { status: 200 });
      }
      // Parse Stripe-Signature header format: t=timestamp,v1=signature[,...]
      const parts = sigHeader.split(',').map(s => s.trim());
      const tPart = parts.find(p => p.startsWith('t='));
      const v1Parts = parts.filter(p => p.startsWith('v1='));
      if (!tPart || v1Parts.length === 0) {
        return new Response('bad signature', { status: 400 });
      }
      const t = tPart.substring(2);
      const signedPayload = `${t}.${raw}`;
      const expected = await hmacSHA256Hex(env.STRIPE_WEBHOOK_SECRET, signedPayload);
      const ok = v1Parts.some(v => v.substring(3).toLowerCase() === expected.toLowerCase());
      if (!ok) {
        return new Response('bad signature', { status: 400 });
      }
      // Optional tolerance check (5 minutes)
      const ts = Number(t);
      const tolerance = 5 * 60; // seconds
      if (Number.isFinite(ts)) {
        const nowSec = Math.floor(Date.now() / 1000);
        if (Math.abs(nowSec - ts) > tolerance) return new Response('signature expired', { status: 400 });
      }
      let event: any = {};
      try { event = JSON.parse(raw); } catch { return new Response('bad request', { status: 400 }); }
      try { await handleStripeEvent(env, event); } catch {}
      return new Response('ok', { status: 200 });
    }

    if (url.pathname === '/v1/org' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      try {
        const found = await getOrCreateOrgForOwner(env, authUser);
        const org = found.org;
        const justCreated = found.created;
        // Fire-and-forget welcome email on first creation
        if (justCreated && authUser.email) {
          const first = authUser.email.split('@')[0] || 'there';
          const base = (env.DASH_BASE_URL && env.DASH_BASE_URL.startsWith('http')) ? env.DASH_BASE_URL : (reqOrigin || '');
          const dash = (base || '').replace(/\/$/, '');
          const ctaUrl = dash ? `${dash}/new-site` : '/new-site';
          const ctaText = 'Create your first site';
          ctx.waitUntil(sendWelcomeEmail(env, authUser.email, first, ctaUrl, ctaText));
        }
        return json({
          id: org.id,
          name: org.name,
          plan_id: org.plan_id || 'free',
          stripe_customer_id: org.stripe_customer_id || null,
          created_at: org.created_at,
          price_id: org.price_id || null,
          subscription_status: org.subscription_status || null,
          current_period_end: org.current_period_end || null,
          cancel_at: org.cancel_at || null,
          trial_end: org.trial_end || null,
        }, {}, reqOrigin || '*');
      } catch {
        return json({ id: null, plan_id: 'free' }, {}, reqOrigin || '*');
      }
    }

    // PATCH /v1/org (update name)
    if (url.pathname === '/v1/org' && request.method === 'PATCH') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ error: 'No DB' }, { status: 500 }, reqOrigin || '*');
      try {
        const body = await request.json<{ name?: string }>().catch(() => ({} as any));
        const name = (body?.name || '').trim();
        if (!name) return json({ error: 'name_required' }, { status: 400 }, reqOrigin || '*');
        const { org } = await getOrCreateOrgForOwner(env, authUser);
        await env.DB.prepare('UPDATE orgs SET name = ? WHERE id = ?').bind(name, org.id).run();
        return json({ ok: true, name }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // Public-ish plans listing (read-only) – DB is source of truth
    if (url.pathname === '/v1/plans' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      if (!env.DB) return json({ plans: [] }, {}, reqOrigin || '*');
      try {
        const res = await env.DB
          .prepare('SELECT id, name, monthly_event_limit, stripe_price_id AS price_id, features_json FROM plans ORDER BY CASE id WHEN "free" THEN 0 WHEN "pro" THEN 1 WHEN "team" THEN 2 WHEN "enterprise" THEN 3 ELSE 99 END, name')
          .all<{ id: string; name?: string; monthly_event_limit?: number | null; price_id?: string | null; features_json?: string | null }>();
        const plans = (res.results || []).map((p: any) => ({
          id: p.id as string,
          name: (p.name || p.id) as string,
          monthly_event_limit: p.monthly_event_limit ?? null,
          price_id: p.price_id || null,
          features: (() => { try { return p.features_json ? JSON.parse(p.features_json) : {}; } catch { return {}; } })(),
        }));
        return json({ plans }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // GET /v1/org/members (list)
    if (url.pathname === '/v1/org/members' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ members: [] }, {}, reqOrigin || '*');
      try {
        const { org } = await getOrCreateOrgForOwner(env, authUser);
        // Any active member can view members in this org
        const res = await env.DB
          .prepare('SELECT id, org_id, user_sub, email, role, status, invited_at, joined_at FROM org_members WHERE org_id = ? ORDER BY datetime(invited_at) DESC')
          .bind(org.id)
          .all<{ id: string; org_id: string; user_sub?: string | null; email?: string | null; role: string; status: string; invited_at: string; joined_at?: string | null }>();
        return json({ members: (res.results as any[]) || [] }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // GET /v1/org/members/pending (for current user)
    if (url.pathname === '/v1/org/members/pending' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ invites: [] }, {}, reqOrigin || '*');
      try {
        const email = (authUser.email || '').toLowerCase();
        const nowIso = new Date().toISOString();
        const res = await env.DB
          .prepare('SELECT id, org_id, email, role, status, invited_at, invite_token FROM org_members WHERE status = "pending" AND lower(email) = ? AND (invite_expires_at IS NULL OR invite_expires_at > ?) ORDER BY datetime(invited_at) DESC')
          .bind(email, nowIso)
          .all<{ id: string; org_id: string; email: string; role: string; status: string; invited_at: string; invite_token: string }>();
        return json({ invites: (res.results as any[]) || [] }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // POST /v1/org/members/invite { email, role? }
    if (url.pathname === '/v1/org/members/invite' && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ error: 'No DB' }, { status: 500 }, reqOrigin || '*');
      let body: any = {};
      try { body = await request.json(); } catch {}
      const email = String(body?.email || '').trim();
      const role = String(body?.role || 'member');
      if (!email) return json({ error: 'email_required' }, { status: 400 }, reqOrigin || '*');
      try {
        const { org } = await getOrCreateOrgForOwner(env, authUser);
        // Admins only
        const isAdmin = await ensureOrgAdmin(env, org.id, authUser);
        if (!isAdmin) return json({ error: 'forbidden' }, { status: 403 }, reqOrigin || '*');
        // Soft seat cap enforcement
        const limit = await getOrgSeatsLimit(env, org.id, org.plan_id || 'free');
        const count = await getOrgMemberCount(env, org.id);
        if (typeof limit === 'number' && count >= limit) {
          return json({ error: 'seat_limit_reached' }, { status: 403 }, reqOrigin || '*');
        }
        const token = await generateInviteToken();
        const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        // Replace any existing pending invite for this email in this org
        await env.DB.prepare('DELETE FROM org_members WHERE org_id = ? AND lower(email) = lower(?) AND status = "pending"').bind(org.id, email).run();
        await env.DB
          .prepare(
            `INSERT INTO org_members (id, org_id, user_sub, email, role, status, invited_at, invite_token, invite_expires_at, invited_by)
             VALUES (lower(hex(randomblob(8))), ?, NULL, ?, ?, 'pending', strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, ?)`
          )
          .bind(org.id, email, role, token, expires, authUser.sub || null)
          .run();
        const acceptUrl = buildAcceptUrl(env, token);
        if (env.RESEND_API_KEY && env.INVITE_FROM_EMAIL) {
          const inviterName = authUser.email ? authUser.email.split('@')[0] : undefined;
          try { await sendInviteEmail(env, email, org.name || 'Your team', acceptUrl, inviterName); } catch {}
        }
        return json({ ok: true, accept_url: acceptUrl }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // GET /v1/org/members/accept?token=...
    if (url.pathname === '/v1/org/members/accept' && request.method === 'GET' && url.searchParams.get('token')) {
      const { origin: reqOrigin } = cors(request);
      if (!env.DB) return json({ ok: false, error: 'no_db' }, { status: 500 }, reqOrigin || '*');
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      const token = url.searchParams.get('token') || '';
      try {
        const nowIso = new Date().toISOString();
        const row = await env.DB
          .prepare('SELECT id, org_id, email FROM org_members WHERE invite_token = ? AND status = "pending" AND (invite_expires_at IS NULL OR invite_expires_at > ?)')
          .bind(token, nowIso)
          .first<{ id: string; org_id: string; email: string }>();
        if (!row) return json({ ok: false, error: 'invalid_or_expired' }, { status: 400 }, reqOrigin || '*');
        await env.DB
          .prepare('UPDATE org_members SET status = "active", joined_at = strftime("%Y-%m-%dT%H:%M:%fZ","now"), user_sub = ?, invite_token = NULL, invite_expires_at = NULL WHERE id = ?')
          .bind(authUser.sub || null, row.id)
          .run();
        return json({ ok: true }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ ok: false, error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // POST /v1/org/members/accept (in-app accept latest pending invite for this email)
    if (url.pathname === '/v1/org/members/accept' && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ error: 'No DB' }, { status: 500 }, reqOrigin || '*');
      try {
        const email = (authUser.email || '').toLowerCase();
        const nowIso = new Date().toISOString();
        const pending = await env.DB
          .prepare(`SELECT id FROM org_members 
                    WHERE status = 'pending' AND lower(email) = ? 
                      AND (invite_expires_at IS NULL OR invite_expires_at > ?)
                    ORDER BY datetime(invited_at) DESC LIMIT 1`)
          .bind(email, nowIso)
          .first<{ id: string }>();
        if (!pending?.id) return json({ ok: false, error: 'no_pending' }, { status: 404 }, reqOrigin || '*');
        await env.DB
          .prepare(`UPDATE org_members SET status = 'active', joined_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), user_sub = ?, invite_token = NULL, invite_expires_at = NULL WHERE id = ?`)
          .bind(authUser.sub || null, pending.id)
          .run();
        return json({ ok: true }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // POST /v1/org/members/remove { email?, user_sub? }
    if (url.pathname === '/v1/org/members/remove' && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ error: 'No DB' }, { status: 500 }, reqOrigin || '*');
      let body: any = {};
      try { body = await request.json(); } catch {}
      const email = (body?.email ? String(body.email) : '').trim();
      const user_sub = (body?.user_sub ? String(body.user_sub) : '').trim();
      if (!email && !user_sub) return json({ error: 'identifier_required' }, { status: 400 }, reqOrigin || '*');
      try {
        const { org } = await getOrCreateOrgForOwner(env, authUser);
        // Admins only
        const isAdmin = await ensureOrgAdmin(env, org.id, authUser);
        if (!isAdmin) return json({ error: 'forbidden' }, { status: 403 }, reqOrigin || '*');
        await env.DB
          .prepare(`DELETE FROM org_members WHERE org_id = ? AND (lower(email) = lower(?) OR user_sub = ?)`) 
          .bind(org.id, email || '', user_sub || '')
          .run();
        return json({ ok: true }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // GET /v1/orgs – list orgs the user belongs to (owner or active member)
    if (url.pathname === '/v1/orgs' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ orgs: [] }, {}, reqOrigin || '*');
      try {
        const sql = `
          SELECT o.*, 'owner' AS rel_role, 'active' AS rel_status
          FROM orgs o WHERE o.owner_sub = ?
          UNION ALL
          SELECT o.*, m.role AS rel_role, m.status AS rel_status
          FROM org_members m JOIN orgs o ON o.id = m.org_id
          WHERE m.user_sub = ? AND m.status = 'active' AND o.owner_sub != ?
          ORDER BY created_at DESC
        `;
        const res = await env.DB.prepare(sql).bind(authUser.sub, authUser.sub, authUser.sub).all<any>();
        const rows = (res.results as any[]) || [];
        return json({ orgs: rows.map(r => ({
          id: r.id,
          name: r.name,
          plan_id: r.plan_id,
          created_at: r.created_at,
          rel_role: r.rel_role,
          rel_status: r.rel_status
        })) }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // GET /v1/orgs/:id/members – members of a given org (must belong to org)
    if (url.pathname.startsWith('/v1/orgs/') && url.pathname.endsWith('/members') && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ members: [] }, {}, reqOrigin || '*');
      const partsM = url.pathname.split('/');
      const orgId = partsM[3] || '';
      if (!orgId) return json({ error: 'org_required' }, { status: 400 }, reqOrigin || '*');
      try {
        const role = await getOrgRole(env, orgId, authUser);
        if (!role.is_owner && role.status !== 'active') return json({ error: 'forbidden' }, { status: 403 }, reqOrigin || '*');
        const res = await env.DB
          .prepare('SELECT id, org_id, user_sub, email, role, status, invited_at, joined_at FROM org_members WHERE org_id = ? ORDER BY datetime(invited_at) DESC')
          .bind(orgId)
          .all<any>();
        return json({ members: (res.results as any[]) || [] }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    // POST /v1/orgs/:id/leave – leave an org (must be active member; owners cannot leave)
    if (url.pathname.startsWith('/v1/orgs/') && url.pathname.endsWith('/leave') && request.method === 'POST') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request);
      if (!authUser) return new Response('Unauthorized', { status: 401, headers: { 'access-control-allow-origin': reqOrigin || '*' } });
      if (!env.DB) return json({ error: 'No DB' }, { status: 500 }, reqOrigin || '*');
      const partsL = url.pathname.split('/');
      const orgId = partsL[3] || '';
      if (!orgId) return json({ error: 'org_required' }, { status: 400 }, reqOrigin || '*');
      try {
        // Owners cannot leave via this endpoint
        const r = await getOrgRole(env, orgId, authUser);
        if (r.is_owner) return json({ error: 'owner_cannot_leave' }, { status: 400 }, reqOrigin || '*');
        if (r.status !== 'active') return json({ error: 'not_a_member' }, { status: 400 }, reqOrigin || '*');
        await env.DB.prepare('DELETE FROM org_members WHERE org_id = ? AND user_sub = ?').bind(orgId, authUser.sub).run();
        return json({ ok: true }, {}, reqOrigin || '*');
      } catch (e: any) {
        return json({ error: String(e?.message || e) }, { status: 500 }, reqOrigin || '*');
      }
    }

    if (url.pathname === '/' || url.pathname === '/v1/health') {
      // Best-effort initialize billing tables (no-op if they already exist or D1 is not bound)
      ctx.waitUntil(ensureBillingTables(env).catch(() => {}));
      // Dev-only: auto-migrate feedback table locally if missing
      if (env.FIDBAK_DEV_AUTOMIGRATE === '1') {
        ctx.waitUntil(ensureDevFeedbackTable(env).catch(() => {}));
      }
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
      // Soft quota headers + optional hard enforcement: attempt to resolve org -> plan limit -> current usage
      let quotaHeaders: Record<string, string> | undefined;
      let planIdForQuota: string | undefined;
      let numericLimit: number | null | undefined;
      let usedEvents: number | undefined;
      let subStatus: string | null | undefined;
      let currentPeriodEndIso: string | null | undefined;
      if (env.DB) {
        try {
          // Resolve org and plan for this site
          const row = await env.DB
            .prepare(`SELECT o.id as org_id, o.plan_id as plan_id, o.subscription_status as subscription_status, o.current_period_end as current_period_end FROM sites s JOIN orgs o ON o.id = s.org_id WHERE s.id = ?`)
            .bind(siteId)
            .first<{ org_id?: string; plan_id?: string; subscription_status?: string | null; current_period_end?: string | null }>();
          const planId = row?.plan_id || 'free';
          planIdForQuota = planId;
          subStatus = row?.subscription_status || null;
          currentPeriodEndIso = row?.current_period_end || null;
          // Read plan limit
          const p = await env.DB
            .prepare('SELECT monthly_event_limit FROM plans WHERE id = ?')
            .bind(planId)
            .first<{ monthly_event_limit?: number | null }>();
          const limit = (p && (p.monthly_event_limit === null || typeof p.monthly_event_limit === 'undefined')) ? null : Number(p?.monthly_event_limit || 0);
          numericLimit = limit;
          const usage = await getCurrentMonthUsageForSite(env, siteId);
          usedEvents = usage.events;
          let status: 'ok' | 'nearing' | 'exceeded' = 'ok';
          if (limit !== null && limit > 0) {
            const used = usage.events;
            if (used >= limit) status = 'exceeded';
            else if (used >= Math.max(1, Math.floor(limit * 0.8))) status = 'nearing';
            quotaHeaders = {
              'X-Fidbak-Quota': status,
              'X-Fidbak-Quota-Limit': String(limit),
              'X-Fidbak-Quota-Used': String(used),
              'X-Fidbak-Plan': planId,
            };
          } else {
            quotaHeaders = {
              'X-Fidbak-Quota': 'ok',
              'X-Fidbak-Quota-Limit': 'unlimited',
              'X-Fidbak-Quota-Used': String(usage.events),
              'X-Fidbak-Plan': planId,
            };
          }
        } catch {}
      }
      // Optional hard enforcement using env flags
      const enforce = env.FIDBAK_ENFORCE_QUOTAS === '1';
      if (enforce) {
        let blockReason: string | null = null;
        // 1) Over monthly limit
        if (numericLimit !== null && typeof numericLimit === 'number' && typeof usedEvents === 'number' && usedEvents >= numericLimit) {
          blockReason = 'quota_exceeded';
        }
        // 2) Billing status gates
        const nowMs = Date.now();
        const graceDays = Number(env.FIDBAK_BILLING_GRACE_DAYS || '7');
        const graceMs = isFinite(graceDays) ? graceDays * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
        const endMs = currentPeriodEndIso ? new Date(currentPeriodEndIso).getTime() : null;
        if (!blockReason && subStatus) {
          const status = String(subStatus);
          if (status === 'unpaid' || status === 'incomplete_expired') {
            blockReason = 'billing_unpaid';
          } else if (status === 'past_due') {
            if (endMs && nowMs > endMs + graceMs) blockReason = 'billing_past_due';
          } else if (status === 'canceled') {
            if (endMs && nowMs > endMs) {
              // After cancellation period ends, enforce free cap if exceeded
              try {
                const freeRow = await env.DB!.prepare('SELECT monthly_event_limit FROM plans WHERE id = ?').bind('free').first<{ monthly_event_limit?: number | null }>();
                const freeLimit = (freeRow && (freeRow.monthly_event_limit === null || typeof freeRow.monthly_event_limit === 'undefined')) ? null : Number(freeRow?.monthly_event_limit || 0);
                if (freeLimit !== null && typeof usedEvents === 'number' && usedEvents >= freeLimit) blockReason = 'subscription_canceled';
              } catch {}
            }
          }
        }
        if (blockReason) {
          const resp = json({ accepted: false, reason: blockReason }, { status: 429 }, allow);
          if (quotaHeaders) {
            for (const [k, v] of Object.entries(quotaHeaders)) (resp.headers as any).set(k, v);
          }
          return resp;
        }
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
      // Best-effort usage metering (non-blocking; fully optional)
      ctx.waitUntil(
        recordUsageEvent(env, row.site_id, row.id, row.created_at).catch((e: unknown) => {
          try { console.warn('fidbak: usage record failed', row.site_id, row.id, (e as any)?.message || e); } catch {}
        }),
      );
      const resp = json({ accepted: true, id: row.id }, { status: 202 }, allow);
      if (quotaHeaders) {
        for (const [k, v] of Object.entries(quotaHeaders)) (resp.headers as any).set(k, v);
      }
      return resp;
    }

    // GET /v1/sites  (list sites for current org)
    if (url.pathname === '/v1/sites' && request.method === 'GET') {
      const { origin: reqOrigin } = cors(request);
      const authUser = await getAuth(env, request).catch(() => undefined);
      try {
        const found = authUser ? await getOrCreateOrgForOwner(env, authUser) : undefined;
        const orgId = found?.org?.id as string | undefined;
        let sites: any[] = [];
        if (env.DB && orgId) {
          try {
            const res = await env.DB
              .prepare(`SELECT s.id, s.name, s.cors_json, s.created_at, s.verified_at
                        FROM sites s WHERE s.org_id = ? ORDER BY datetime(s.created_at) DESC`)
              .bind(orgId)
              .all<{ id: string; name?: string; cors_json?: string; created_at: string; verified_at?: string | null }>();
            const rows = (res.results as any[]) || [];
            sites = rows.map(r => ({
              id: r.id,
              name: r.name,
              owner_email: null,
              cors: r.cors_json ? JSON.parse(r.cors_json) : [],
              created_at: r.created_at,
              verified_at: r.verified_at ?? null,
            }));
          } catch {
            // Fallback to legacy owner-scoped listing
            const ownerEmail = (authUser?.email || '').trim();
            sites = await listSitesByOwner(env, { sub: authUser?.sub, email: ownerEmail || undefined });
          }
        } else {
          const ownerEmail = (authUser?.email || '').trim();
          sites = await listSitesByOwner(env, { sub: authUser?.sub, email: ownerEmail || undefined });
        }
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

    // GET /v1/sites/:id/usage/month (minimal usage for current month)
    {
      const m = url.pathname.match(/^\/v1\/sites\/([^/]+)\/usage\/month$/);
      if (m && request.method === 'GET') {
        const siteId = decodeURIComponent(m[1] || '');
        const { origin: reqOrigin } = cors(request);
        try {
          const usage = await getCurrentMonthUsageForSite(env, siteId);
          return json({ siteId, month: usage.month, events: usage.events }, {}, reqOrigin || '*');
        } catch (e) {
          // If billing tables/columns do not exist, return zeros
          const now = new Date();
          const yyyymm = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
          return json({ siteId, month: yyyymm, events: 0 }, {}, reqOrigin || '*');
        }
      }
    }


    // POST /v1/sites  (self-serve create, org-scoped)
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
      // Resolve current org and enforce plan site limit
      const { org } = await getOrCreateOrgForOwner(env, authUser);
      const features = await getPlanFeatures(env, org?.plan_id || 'free');
      const maxSites = Number(features?.sites ?? 1);
      const originToAllow = (body?.origin || '').trim();
      const moreOrigins = Array.isArray(body?.origins) ? body.origins.filter((o: any) => typeof o === 'string' && /^https?:\/\//.test(o)).map((s: string) => s.trim()) : [];
      if (!id || !/^[a-z0-9-]{3,}$/.test(id)) return bad('invalid_site_id', reqOrigin || '*');
      if (!originToAllow || !/^https?:\/\//.test(originToAllow)) return bad('invalid_origin', reqOrigin || '*');

      const verify_token = crypto.randomUUID();
      const dashboardOrigin = env.FIDBAK_DASH_ORIGIN || 'https://fidbak-dash.pages.dev';
      const set = new Set<string>([originToAllow, ...moreOrigins, dashboardOrigin]);
      const corsArr = Array.from(set);
      try {
        // Enforce site count limit by org
        if (env.DB && org?.id) {
          try {
            const cnt = await env.DB
              .prepare('SELECT COUNT(*) AS c FROM sites WHERE org_id = ?')
              .bind(org.id)
              .first<{ c: number }>();
            const current = Number(cnt?.c || 0);
            if (Number.isFinite(maxSites) && current >= maxSites) {
              return json({ error: 'site_limit_reached' }, { status: 403 }, reqOrigin || '*');
            }
          } catch {}
        }
        await upsertSite(env, { id, name, owner_email: authUser.email || null, owner_user_id: authUser.sub, org_id: org?.id || null, cors: corsArr, verify_token });
        // Optional initial webhook
        if (body?.webhook && typeof body.webhook === 'object') {
          const wu = String(body.webhook.url || '').trim();
          const ws = typeof body.webhook.secret === 'string' ? body.webhook.secret : undefined;
          const active = body.webhook.active !== false;
          if (/^https?:\/\//.test(wu)) {
            await createSiteWebhook(env, id, { url: wu, secret: ws, active });
          }
        }
        const dashboard = env.FIDBAK_DASHBOARD_BASE ? `${env.FIDBAK_DASHBOARD_BASE}/?siteId=${encodeURIComponent(id)}` : undefined;
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
  data: { id: string; name: string; owner_email?: string | null; owner_user_id?: string | null; org_id?: string | null; cors: string[]; verify_token?: string },
) {
  if (env.DB) {
    const cors_json = JSON.stringify(data.cors || []);
    // Try including owner_user_id (new column). Fallback to legacy insert on error.
    try {
      await env.DB
        .prepare(
          `INSERT INTO sites (id, name, owner_email, owner_user_id, org_id, cors_json, created_at, verify_token)
           VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)
           ON CONFLICT(id) DO UPDATE SET name=excluded.name, owner_email=excluded.owner_email, owner_user_id=excluded.owner_user_id, org_id=COALESCE(excluded.org_id, sites.org_id), cors_json=excluded.cors_json`,
        )
        .bind(data.id, data.name, data.owner_email || null, data.owner_user_id || null, data.org_id || null, cors_json, data.verify_token || null)
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
      if (env.FIDBAK_DEV_AUTOMIGRATE === '1') {
        await ensureDevFeedbackTable(env);
      }
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
      try { console.log('fidbak: feedback inserted', row.site_id, row.id, row.created_at); } catch {}
      return;
    } catch (e) {
      try {
        console.warn('fidbak: feedback insert failed, using memory fallback', row.site_id, row.id, (e as any)?.message || e);
      } catch {}
    }
  }
  MEM.feedback.unshift(row);
}

// Dev-only: ensure feedback table exists locally to avoid silent memory fallback during testing
async function ensureDevFeedbackTable(env: Env) {
  if (!env.DB) return;
  // Only run in dev mode when explicitly enabled
  if (env.FIDBAK_DEV_AUTOMIGRATE !== '1') return;
  try {
    const exists = await env.DB
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")
      .first<any>();
    if (exists) return;
  } catch {}
  try {
    await env.DB.exec(
      `CREATE TABLE IF NOT EXISTS feedback (
         id TEXT PRIMARY KEY,
         site_id TEXT NOT NULL,
         page_id TEXT,
         rating TEXT NOT NULL,
         comment TEXT,
         email TEXT,
         context_json TEXT,
         ip_hash TEXT,
         created_at TEXT NOT NULL
       );
       CREATE INDEX IF NOT EXISTS idx_feedback_site_created ON feedback(site_id, datetime(created_at));`
    );
    try { console.log('fidbak: dev automigrate created feedback table'); } catch {}
  } catch (e) {
    try { console.warn('fidbak: dev automigrate failed', (e as any)?.message || e); } catch {}
  }
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

// ---------- billing helpers (Phase 1: optional per-site metering) ----------
async function ensureBillingTables(env: Env) {
  if (!env.DB) return;
  try {
    await env.DB.exec(
      `CREATE TABLE IF NOT EXISTS usage_events_site (
         id TEXT PRIMARY KEY,
         site_id TEXT NOT NULL,
         ts TEXT NOT NULL,
         idem_key TEXT NOT NULL
       );`
    );
  } catch {}
  try {
    await env.DB.exec(
      `CREATE INDEX IF NOT EXISTS idx_usage_events_site_site_ts ON usage_events_site(site_id, ts);`
    );
  } catch {}
  try {
    await env.DB.exec(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_events_site_idem ON usage_events_site(idem_key);`
    );
  } catch {}
  try {
    await env.DB.exec(
      `CREATE TABLE IF NOT EXISTS usage_monthly_site (
         site_id TEXT NOT NULL,
         yyyymm TEXT NOT NULL,
         events INTEGER NOT NULL DEFAULT 0,
         PRIMARY KEY (site_id, yyyymm)
       );`
    );
  } catch {}
}

async function recordUsageEvent(env: Env, siteId: string, feedbackId: string, createdAtIso: string) {
  if (!env.DB) return;
  try {
    await ensureBillingTables(env);
    const ts = createdAtIso || new Date().toISOString();
    const d = new Date(ts);
    const yyyymm = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
    // Insert event (idempotent)
    await env.DB
      .prepare('INSERT OR IGNORE INTO usage_events_site (id, site_id, ts, idem_key) VALUES (?, ?, ?, ?)')
      .bind(feedbackId, siteId, ts, feedbackId)
      .run();
    // Upsert monthly aggregate
    await env.DB
      .prepare('INSERT INTO usage_monthly_site (site_id, yyyymm, events) VALUES (?, ?, 1) ON CONFLICT(site_id, yyyymm) DO UPDATE SET events = events + 1')
      .bind(siteId, yyyymm)
      .run();
  } catch (e) {}
}

async function getCurrentMonthUsageForSite(env: Env, siteId: string): Promise<{ month: string; events: number }> {
  const now = new Date();
  const yyyymm = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  if (!env.DB) return { month: yyyymm, events: 0 };
  // Step 1: monthly aggregate
  try {
    const row = await env.DB
      .prepare('SELECT events FROM usage_monthly_site WHERE site_id = ? AND yyyymm = ?')
      .bind(siteId, yyyymm)
      .first<{ events: number }>();
    if (row && typeof row.events === 'number' && Number(row.events) > 0) {
      return { month: yyyymm, events: Number(row.events) };
    }
  } catch (e) {}

  // Step 2: events table count
  try {
    const res = await env.DB
      .prepare("SELECT COUNT(*) AS c FROM usage_events_site WHERE site_id = ? AND substr(ts,1,7) = ?")
      .bind(siteId, yyyymm)
      .first<{ c: number }>();
    const eventsFromEvents = Number(res?.c || 0);
    if (eventsFromEvents > 0) return { month: yyyymm, events: eventsFromEvents };
  } catch (e) {}

  // Step 3: direct feedback count (robust, no datetime parsing)
  try {
    const res2 = await env.DB
      .prepare("SELECT COUNT(*) AS c FROM feedback WHERE site_id = ? AND substr(created_at,1,7) = ?")
      .bind(siteId, yyyymm)
      .first<{ c: number }>();
    return { month: yyyymm, events: Number(res2?.c || 0) };
  } catch (e) {
    return { month: yyyymm, events: 0 };
  }
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

// ---------- org seats helpers ----------
async function getOrgSeatsLimit(env: Env, orgId: string, planId: string): Promise<number | null> {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare('SELECT features_json FROM plans WHERE id = ?').bind(planId).first<{ features_json?: string }>();
    const features = row?.features_json ? JSON.parse(row.features_json) : {};
    const seats = features?.seats;
    if (seats === 'custom' || seats === null || typeof seats === 'undefined') return null;
    const n = Number(seats);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch { return null; }
}

async function getOrgMemberCount(env: Env, orgId: string): Promise<number> {
  if (!env.DB) return 0;
  try {
    const row = await env.DB
      .prepare("SELECT COUNT(*) AS c FROM org_members WHERE org_id = ? AND status IN ('pending','active')")
      .bind(orgId)
      .first<{ c: number }>();
    return Number(row?.c || 0);
  } catch { return 0; }
}
