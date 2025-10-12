import { getOrgByStripeCustomerId, updateOrgSubscriptionFields } from '../../repositories/orgs.repo';

function mapPriceToPlan(env: { STRIPE_PRICE_PRO?: string; STRIPE_PRICE_TEAM?: string; STRIPE_PRICE_ENTERPRISE?: string }, priceId?: string): string | null {
  if (!priceId) return null;
  if (env.STRIPE_PRICE_PRO === priceId) return 'pro';
  if (env.STRIPE_PRICE_TEAM === priceId) return 'team';
  if (env.STRIPE_PRICE_ENTERPRISE === priceId) return 'enterprise';
  return null;
}

export async function handleStripeEvent(env: { DB?: D1Database; STRIPE_PRICE_PRO?: string; STRIPE_PRICE_TEAM?: string; STRIPE_PRICE_ENTERPRISE?: string }, event: any) {
  if (!env.DB) return;
  const type = String(event?.type || '');
  const data = event?.data?.object || {};

  if (type === 'checkout.session.completed') {
    const customer = data?.customer as string | undefined;
    const sub = data?.subscription || {};
    const priceId = sub?.items?.data?.[0]?.price?.id || data?.display_items?.[0]?.price?.id || undefined;
    const status = sub?.status || 'active';
    const current_period_end = sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : undefined;
    if (customer) {
      const org = await getOrgByStripeCustomerId(env, customer);
      const plan = mapPriceToPlan(env, priceId) || 'pro';
      if (org) {
        await updateOrgSubscriptionFields(env, org.id, {
          plan_id: plan,
          price_id: priceId || null,
          subscription_status: status,
          current_period_end,
        });
      }
    }
    return;
  }

  if (type === 'customer.subscription.updated' || type === 'customer.subscription.created') {
    const sub = data;
    const customer = sub?.customer as string | undefined;
    const priceId = sub?.items?.data?.[0]?.price?.id as string | undefined;
    const status = sub?.status || null;
    const current_period_end = sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
    const cancel_at = sub?.cancel_at ? new Date(sub.cancel_at * 1000).toISOString() : null;
    const trial_end = sub?.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null;
    if (customer) {
      const org = await getOrgByStripeCustomerId(env, customer);
      const plan = mapPriceToPlan(env, priceId);
      if (org) {
        await updateOrgSubscriptionFields(env, org.id, {
          plan_id: plan || null,
          price_id: priceId || null,
          subscription_status: status,
          current_period_end,
          cancel_at,
          trial_end,
        });
      }
    }
    return;
  }

  if (type === 'customer.subscription.deleted') {
    const customer = data?.customer as string | undefined;
    if (customer) {
      const org = await getOrgByStripeCustomerId(env, customer);
      if (org) await updateOrgSubscriptionFields(env, org.id, { plan_id: 'free', subscription_status: 'canceled' });
    }
    return;
  }
}
