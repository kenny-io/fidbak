export type PlanRow = {
  id: string;
  name?: string;
  monthly_event_limit?: number | null;
  price_id?: string | null;
  features_json?: string | null;
};

export type Plan = {
  id: string;
  name: string;
  monthly_event_limit: number | null;
  price_id: string | null;
  features: any;
};

export async function listPlans(env: { DB?: D1Database }): Promise<Plan[]> {
  if (!env.DB) return [];
  const res = await env.DB
    .prepare('SELECT id, name, monthly_event_limit, stripe_price_id AS price_id, features_json FROM plans ORDER BY CASE id WHEN "free" THEN 0 WHEN "pro" THEN 1 WHEN "team" THEN 2 WHEN "enterprise" THEN 3 ELSE 99 END, name')
    .all<PlanRow>();
  const rows = (res.results || []) as any[];
  return rows.map((p) => ({
    id: p.id as string,
    name: (p.name || p.id) as string,
    monthly_event_limit: p.monthly_event_limit ?? null,
    price_id: p.price_id || null,
    features: (() => { try { return p.features_json ? JSON.parse(p.features_json) : {}; } catch { return {}; } })(),
  }));
}
