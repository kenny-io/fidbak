export async function getOrCreateOrgForOwner(env: { DB?: D1Database }, owner: { sub?: string; email?: string }): Promise<{ org: any; created: boolean }> {
  if (!env.DB) throw new Error('DB not configured');
  const sub = owner.sub || null;
  const email = owner.email || null;
  // Prefer an active membership org for this user
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
  // Fallback to an org owned by this user (sub preferred, then email)
  let org = await env.DB.prepare('SELECT * FROM orgs WHERE owner_sub = ? LIMIT 1').bind(sub).first<any>();
  if (!org && email) {
    org = await env.DB.prepare('SELECT * FROM orgs WHERE owner_email = ? LIMIT 1').bind(email).first<any>();
  }
  if (org) return { org, created: false } as any;
  // Create new org on-the-fly with Free plan (personal org)
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  await env.DB
    .prepare('INSERT INTO orgs (id, name, owner_sub, owner_email, plan_id, stripe_customer_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, email ? `${email.split('@')[0]}'s Org` : 'My Org', sub, email, 'free', null, createdAt)
    .run();
  const createdOrg = await env.DB.prepare('SELECT * FROM orgs WHERE id = ?').bind(id).first<any>();
  return { org: createdOrg as any, created: true };
}

export async function getOrgByStripeCustomerId(env: { DB?: D1Database }, customerId: string): Promise<any | null> {
  if (!env.DB) return null;
  return await env.DB.prepare('SELECT * FROM orgs WHERE stripe_customer_id = ? LIMIT 1').bind(customerId).first<any>();
}

export async function setOrgStripeCustomerId(env: { DB?: D1Database }, orgId: string, customerId: string | null): Promise<void> {
  if (!env.DB) return;
  await env.DB.prepare('UPDATE orgs SET stripe_customer_id = ? WHERE id = ?').bind(customerId, orgId).run();
}

export async function updateOrgSubscriptionFields(env: { DB?: D1Database }, orgId: string, fields: {
  plan_id?: string | null;
  price_id?: string | null;
  subscription_status?: string | null;
  current_period_end?: string | null;
  cancel_at?: string | null;
  trial_end?: string | null;
}): Promise<void> {
  if (!env.DB) return;
  const sql = `UPDATE orgs SET
    plan_id = COALESCE(?, plan_id),
    price_id = ?,
    subscription_status = ?,
    current_period_end = ?,
    cancel_at = ?,
    trial_end = ?
  WHERE id = ?`;
  await env.DB.prepare(sql).bind(
    fields.plan_id ?? null,
    fields.price_id ?? null,
    fields.subscription_status ?? null,
    fields.current_period_end ?? null,
    fields.cancel_at ?? null,
    fields.trial_end ?? null,
    orgId,
  ).run();
}
