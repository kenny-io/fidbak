// Stripe price caching (24h) service
export async function fetchStripePriceWithCache(env: {
  DB?: D1Database;
  STRIPE_SECRET_KEY?: string;
}, priceId: string | null | undefined): Promise<{ unit_amount: number | null; currency: string | null; interval: string | null } | null> {
  if (!priceId) return null;
  if (!env.DB) return null;
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS stripe_price_cache (price_id TEXT PRIMARY KEY, unit_amount INTEGER, currency TEXT, interval TEXT, cached_at TEXT)').run();
  } catch {}
  // Try cache first
  try {
    const row = await env.DB.prepare('SELECT unit_amount, currency, interval, cached_at FROM stripe_price_cache WHERE price_id = ?').bind(priceId).first<{ unit_amount?: number | null; currency?: string | null; interval?: string | null; cached_at?: string }>();
    if (row) {
      const cachedAt = row.cached_at ? Date.parse(row.cached_at) : 0;
      const ageMs = Date.now() - (Number.isFinite(cachedAt) ? cachedAt : 0);
      if (ageMs < 24 * 60 * 60 * 1000) {
        return { unit_amount: row.unit_amount ?? null, currency: row.currency ?? null, interval: row.interval ?? null };
      }
    }
  } catch {}
  // Fetch live from Stripe
  if (!env.STRIPE_SECRET_KEY) return null;
  try {
    const resp = await fetch(`https://api.stripe.com/v1/prices/${encodeURIComponent(priceId)}`, {
      headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
    });
    if (!resp.ok) return null;
    const data: any = await resp.json();
    const unit_amount = typeof data.unit_amount === 'number' ? data.unit_amount : null;
    const currency = typeof data.currency === 'string' ? data.currency : null;
    const interval = data?.recurring?.interval || null;
    try {
      await env.DB.prepare('INSERT INTO stripe_price_cache (price_id, unit_amount, currency, interval, cached_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(price_id) DO UPDATE SET unit_amount=excluded.unit_amount, currency=excluded.currency, interval=excluded.interval, cached_at=excluded.cached_at')
        .bind(priceId, unit_amount, currency, interval, new Date().toISOString()).run();
    } catch {}
    return { unit_amount, currency, interval };
  } catch {
    return null;
  }
}
