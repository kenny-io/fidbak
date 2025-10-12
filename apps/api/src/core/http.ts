export function json(data: unknown, init: ResponseInit = {}, origin?: string): Response {
  const h = new Headers(init.headers);
  h.set('content-type', 'application/json; charset=utf-8');
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response(JSON.stringify(data), { ...init, headers: h });
}

export function cors(request: Request): { origin: string | undefined; isPreflight: boolean } {
  const origin = request.headers.get('origin') || undefined;
  const isPreflight = request.method === 'OPTIONS';
  return { origin, isPreflight };
}

export function ok(init: ResponseInit = {}, origin?: string): Response {
  const h = new Headers(init.headers);
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response('ok', { ...init, headers: h });
}

export function notFound(origin?: string): Response {
  const h = new Headers();
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response('Not found', { status: 404, headers: h });
}

export function bad(msg: string, origin?: string): Response {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8' });
  if (origin) h.set('access-control-allow-origin', origin);
  return new Response(JSON.stringify({ error: msg }), { status: 400, headers: h });
}
