// Stripe billing helpers

export async function stripePost(env: { STRIPE_SECRET_KEY?: string }, url: string, body: URLSearchParams, idempotencyKey?: string): Promise<any> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  const res = await fetch(url, {
    method: 'POST',
    headers,
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

export async function createStripeCheckoutSession(env: { STRIPE_SECRET_KEY?: string }, args: { customer?: string; customer_email?: string; priceId: string; mode: 'subscription'; success_url: string; cancel_url: string }, idem?: string) {
  const body = new URLSearchParams();
  body.set('mode', args.mode);
  if (args.customer) body.set('customer', args.customer);
  if (args.customer_email) body.set('customer_email', args.customer_email);
  body.set('line_items[0][price]', args.priceId);
  body.set('line_items[0][quantity]', '1');
  body.set('success_url', args.success_url);
  body.set('cancel_url', args.cancel_url);
  const json = await stripePost(env, 'https://api.stripe.com/v1/checkout/sessions', body, idem);
  return json;
}

export async function createStripePortalSession(env: { STRIPE_SECRET_KEY?: string }, customerId: string, returnUrl: string) {
  const body = new URLSearchParams();
  body.set('customer', customerId);
  body.set('return_url', returnUrl);
  const json = await stripePost(env, 'https://api.stripe.com/v1/billing_portal/sessions', body);
  return json;
}
