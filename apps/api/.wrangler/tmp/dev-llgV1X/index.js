var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-iNJs4b/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
__name(checkURL, "checkURL");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// .wrangler/tmp/bundle-iNJs4b/strip-cf-connecting-ip-header.js
function stripCfConnectingIPHeader(input, init) {
  const request = new Request(input, init);
  request.headers.delete("CF-Connecting-IP");
  return request;
}
__name(stripCfConnectingIPHeader, "stripCfConnectingIPHeader");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    return Reflect.apply(target, thisArg, [
      stripCfConnectingIPHeader.apply(null, argArray)
    ]);
  }
});

// src/index.ts
var MEM = { feedback: [] };
var RATE = /* @__PURE__ */ new Map();
var SITES = {
  "demo-site": {
    name: "Demo Site",
    // In real env, require server-side signing using per-site secret not shared with client.
    // For dev we can skip or set a known secret.
    // hmac_secret: 'dev-secret',
    cors: ["http://localhost:5173", "http://localhost:5175", "http://localhost:5181"]
  }
};
function json(data, init = {}, origin) {
  const h = new Headers(init.headers);
  h.set("content-type", "application/json; charset=utf-8");
  if (origin)
    h.set("access-control-allow-origin", origin);
  return new Response(JSON.stringify(data), { ...init, headers: h });
}
__name(json, "json");
function cors(request) {
  const origin = request.headers.get("origin") || void 0;
  const isPreflight = request.method === "OPTIONS";
  return { origin, isPreflight };
}
__name(cors, "cors");
function notFound(origin) {
  const h = new Headers();
  if (origin)
    h.set("access-control-allow-origin", origin);
  return new Response("Not found", { status: 404, headers: h });
}
__name(notFound, "notFound");
function bad(msg, origin) {
  const h = new Headers({ "content-type": "application/json; charset=utf-8" });
  if (origin)
    h.set("access-control-allow-origin", origin);
  return new Response(JSON.stringify({ error: msg }), { status: 400, headers: h });
}
__name(bad, "bad");
function ipFrom(req) {
  return req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || req.ip || "";
}
__name(ipFrom, "ipFrom");
function hashIp(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++)
    h = h * 31 + ip.charCodeAt(i) >>> 0;
  return String(h);
}
__name(hashIp, "hashIp");
function rateLimit(ip, siteId, limit = 8, windowMs = 6e4) {
  const key = `${ip}|${siteId}`;
  const now = Date.now();
  const arr = RATE.get(key) || [];
  const kept = arr.filter((t) => now - t < windowMs);
  if (kept.length >= limit)
    return false;
  kept.push(now);
  RATE.set(key, kept);
  return true;
}
__name(rateLimit, "rateLimit");
async function hmacSHA256Hex(secret, payload) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const bytes = new Uint8Array(sig);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hmacSHA256Hex, "hmacSHA256Hex");
function corsForSite(siteId, origin) {
  if (!origin)
    return "*";
  if (!siteId)
    return origin;
  const site = SITES[siteId];
  if (!site?.cors)
    return origin;
  return site.cors.includes(origin) ? origin : void 0;
}
__name(corsForSite, "corsForSite");
var src_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { origin, isPreflight } = cors(request);
    if (isPreflight) {
      const h = new Headers({
        "access-control-allow-origin": origin || "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type,x-fidbak-signature"
      });
      return new Response(null, { status: 204, headers: h });
    }
    if (url.pathname === "/" || url.pathname === "/v1/health") {
      return json({ ok: true }, {}, origin || "*");
    }
    if (url.pathname === "/v1/feedback" && request.method === "POST") {
      const ip = ipFrom(request);
      let raw = "";
      try {
        raw = await request.text();
      } catch {
        return bad("invalid body", origin || "*");
      }
      let body;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return bad("invalid json", origin || "*");
      }
      const { siteId, pageId, rating } = body || {};
      if (!siteId || !pageId || rating !== "up" && rating !== "down") {
        return bad("missing fields", origin || "*");
      }
      const policy = body && typeof body.policy === "object" ? body.policy : void 0;
      let allow = corsForSite(siteId, origin || void 0);
      if (origin && policy?.corsAllow && Array.isArray(policy.corsAllow)) {
        allow = policy.corsAllow.includes(origin) ? origin : allow;
      }
      if (!allow) {
        return new Response("Forbidden", { status: 403 });
      }
      const site = await getSite(env, siteId);
      const sig = request.headers.get("x-fidbak-signature") || "";
      const secret = site?.hmac_secret;
      const requireHmac = policy?.requireHmac === true || !!secret;
      if (requireHmac && secret) {
        const expect = await hmacSHA256Hex(secret, raw);
        if (sig.toLowerCase() !== expect.toLowerCase()) {
          return json({ accepted: false, reason: "bad_signature" }, { status: 401 }, allow);
        }
      } else if (requireHmac) {
        return json({ accepted: false, reason: "hmac_required" }, { status: 401 }, allow);
      }
      if (policy?.ipAllow && Array.isArray(policy.ipAllow) && policy.ipAllow.length > 0) {
        if (!policy.ipAllow.includes(ip)) {
          return json({ accepted: false, reason: "ip_forbidden" }, { status: 403 }, allow);
        }
      }
      if (!rateLimit(ip, siteId)) {
        return json({ accepted: false, reason: "rate_limited" }, { status: 429 }, allow);
      }
      if (policy?.rateLimit) {
        const windowMs = Math.max(1e3, Math.min(10 * 6e4, Number(policy.rateLimit.windowMs || 6e4)));
        const max = Math.max(1, Math.min(120, Number(policy.rateLimit.max || 8)));
        const key = `${ip}|${siteId}|policy`;
        const now = Date.now();
        const arr = RATE.get(key) || [];
        const kept = arr.filter((t) => now - t < windowMs);
        if (kept.length >= max) {
          return json({ accepted: false, reason: "rate_limited_policy" }, { status: 429 }, allow);
        }
        kept.push(now);
        RATE.set(key, kept);
      }
      const row = {
        id: crypto.randomUUID(),
        site_id: siteId,
        page_id: pageId,
        rating,
        comment: typeof body.comment === "string" ? body.comment.slice(0, 5e3) : void 0,
        email: typeof body.email === "string" ? body.email.slice(0, 320) : void 0,
        context_json: body.context || {},
        ip_hash: hashIp(ip),
        created_at: (/* @__PURE__ */ new Date()).toISOString()
      };
      await storeFeedback(env, row);
      const destinations = Array.isArray(body.destinations) ? body.destinations : body.destinations ? [body.destinations] : void 0;
      ctx.waitUntil(
        fanout(
          env,
          row,
          destinations,
          typeof body.webhookSecret === "string" ? body.webhookSecret : void 0,
          policy
        ).catch(() => {
        })
      );
      return json({ accepted: true, id: row.id }, { status: 202 }, allow);
    }
    const match = url.pathname.match(/^\/v1\/sites\/([^/]+)\/feedback$/);
    if (match && request.method === "GET") {
      const siteId = decodeURIComponent(match[1] || "");
      const allow = corsForSite(siteId, origin || void 0) || origin || "*";
      const rating = url.searchParams.get("rating");
      const q = url.searchParams.get("q");
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "50", 10)));
      const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10));
      let items;
      let total = 0;
      if (env.DB) {
        try {
          const stmt = env.DB.prepare(
            `SELECT id, site_id, page_id, rating, comment, email, context_json, ip_hash, created_at
             FROM feedback WHERE site_id = ?
             ${rating ? "AND rating = ?" : ""}
             ${q ? "AND comment LIKE ?" : ""}
             ORDER BY datetime(created_at) DESC
             LIMIT ? OFFSET ?`
          );
          const binds = [siteId];
          if (rating)
            binds.push(rating);
          if (q)
            binds.push(`%${q}%`);
          binds.push(limit, offset);
          const res = await stmt.bind(...binds).all();
          items = res.results || [];
          const countStmt = env.DB.prepare(
            `SELECT COUNT(*) AS c FROM feedback WHERE site_id = ?
             ${rating ? "AND rating = ?" : ""}
             ${q ? "AND comment LIKE ?" : ""}`
          );
          const countRes = await countStmt.bind(...[siteId, ...rating ? [rating] : [], ...q ? [`%${q}%`] : []]).first();
          total = Number(countRes?.c || 0);
        } catch {
          let all = MEM.feedback.filter((f) => f.site_id === siteId);
          if (rating)
            all = all.filter((f) => f.rating === rating);
          if (q)
            all = all.filter((f) => (f.comment || "").toLowerCase().includes(q.toLowerCase()));
          total = all.length;
          items = all.slice(offset, offset + limit);
        }
      } else {
        let all = MEM.feedback.filter((f) => f.site_id === siteId);
        if (rating)
          all = all.filter((f) => f.rating === rating);
        if (q)
          all = all.filter((f) => (f.comment || "").toLowerCase().includes(q.toLowerCase()));
        total = all.length;
        items = all.slice(offset, offset + limit);
      }
      return json({ items, total, nextOffset: Math.min(total, offset + items.length) }, {}, allow);
    }
    const matchSummary = url.pathname.match(/^\/v1\/sites\/([^/]+)\/summary$/);
    if (matchSummary && request.method === "GET") {
      const siteId = decodeURIComponent(matchSummary[1] || "");
      const allow = corsForSite(siteId, origin || void 0) || origin || "*";
      const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get("days") || "7", 10)));
      const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1e3).toISOString();
      if (env.DB) {
        try {
          const totalRow = await env.DB.prepare(
            "SELECT COUNT(*) as c FROM feedback WHERE site_id = ?"
          ).bind(siteId).first();
          const windowRow = await env.DB.prepare(
            `SELECT SUM(CASE WHEN rating='up' THEN 1 ELSE 0 END) as up,
                    SUM(CASE WHEN rating='down' THEN 1 ELSE 0 END) as down
             FROM feedback WHERE site_id = ? AND datetime(created_at) >= datetime(?)`
          ).bind(siteId, sinceIso).first();
          const up2 = Number(windowRow?.up || 0);
          const down2 = Number(windowRow?.down || 0);
          const total2 = Number(totalRow?.c || 0);
          return json({ total: total2, lastN: { days, up: up2, down: down2, total: up2 + down2 } }, {}, allow);
        } catch {
        }
      }
      const all = MEM.feedback.filter((f) => f.site_id === siteId);
      const total = all.length;
      const since = new Date(sinceIso).getTime();
      const windowItems = all.filter((f) => new Date(f.created_at).getTime() >= since);
      const up = windowItems.filter((f) => f.rating === "up").length;
      const down = windowItems.filter((f) => f.rating === "down").length;
      return json({ total, lastN: { days, up, down, total: up + down } }, {}, allow);
    }
    return notFound(origin || "*");
  }
};
async function getSite(env, siteId) {
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        "SELECT hmac_secret, cors_json as cors_json FROM sites WHERE id = ?"
      ).bind(siteId).first();
      if (row) {
        return { hmac_secret: row.hmac_secret, cors: row.cors_json ? JSON.parse(row.cors_json) : void 0 };
      }
    } catch {
    }
  }
  return SITES[siteId];
}
__name(getSite, "getSite");
async function storeFeedback(env, row) {
  if (env.DB) {
    try {
      await env.DB.prepare(
        `INSERT INTO feedback (id, site_id, page_id, rating, comment, email, context_json, ip_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        row.id,
        row.site_id,
        row.page_id,
        row.rating,
        row.comment || null,
        row.email || null,
        JSON.stringify(row.context_json || {}),
        row.ip_hash,
        row.created_at
      ).run();
      return;
    } catch {
    }
  }
  MEM.feedback.unshift(row);
}
__name(storeFeedback, "storeFeedback");
async function fanout(env, row, destinations, webhookSecret, policy) {
  const all = [];
  if (Array.isArray(destinations))
    all.push(...destinations);
  if (env.FIDBAK_SLACK_WEBHOOK)
    all.push(env.FIDBAK_SLACK_WEBHOOK);
  await Promise.all(
    all.map(async (url) => {
      const redacted = url.replace(/(https:\/\/hooks\.slack\.com\/services\/)[^/]+\/[^/]+\/.+/, "$1***");
      try {
        if (/hooks\.slack\.com\/services\//.test(url)) {
          console.log("fidbak: posting to Slack", redacted);
          await postSlack(url, env, row, policy);
        } else {
          const body = JSON.stringify({ type: "fidbak.feedback.v1", data: row });
          const headers = { "content-type": "application/json" };
          if (webhookSecret) {
            headers["x-fidbak-signature"] = await hmacSHA256Hex(webhookSecret, body);
          }
          const resp = await fetch(url, { method: "POST", headers, body });
          if (!resp.ok) {
            console.warn("fidbak: webhook non-2xx", redacted, resp.status);
            try {
              console.warn("fidbak: webhook resp", await resp.text());
            } catch {
            }
          }
        }
      } catch (e) {
        console.warn("fidbak: webhook error", redacted, e?.message || e);
      }
    })
  );
}
__name(fanout, "fanout");
function makeSlackBlocks(env, row) {
  const ctx = row.context_json || {};
  const rating = row.rating === "up" ? "\u{1F44D}" : "\u{1F44E}";
  const title = ctx.title || "";
  const url = ctx.url || row.page_id;
  const ref = ctx.referrer ? `Ref: ${ctx.referrer}` : "";
  const scroll = typeof ctx.scrollPct === "number" ? `Scroll: ${ctx.scrollPct}%` : "";
  const subtitle = [title, row.page_id].filter(Boolean).join(" \u2022 ");
  const footerLink = env.FIDBAK_DASHBOARD_BASE ? `${env.FIDBAK_DASHBOARD_BASE}/?siteId=${encodeURIComponent(row.site_id)}&id=${encodeURIComponent(row.id)}` : "";
  const footer = [row.email || "", footerLink ? `<${footerLink}|Open>` : ""].filter(Boolean).join(" \u2022 ");
  const blocks = [
    { type: "header", text: { type: "plain_text", text: `${rating} Feedback on ${row.page_id}` } },
    ...row.comment ? [{ type: "section", text: { type: "mrkdwn", text: `*Comment*
${row.comment}` } }] : [],
    { type: "section", text: { type: "mrkdwn", text: `*Page* <${url}|${subtitle}>` } },
    ...ref || scroll ? [{ type: "context", elements: [{ type: "mrkdwn", text: [ref, scroll].filter(Boolean).join(" \u2022 ") }] }] : [],
    ...footer ? [{ type: "context", elements: [{ type: "mrkdwn", text: footer }] }] : []
  ];
  return blocks;
}
__name(makeSlackBlocks, "makeSlackBlocks");
async function postSlack(webhook, env, row, policy) {
  const blocks = makeSlackBlocks(env, row);
  const text = `${row.rating === "up" ? "\u{1F44D}" : "\u{1F44E}"} Feedback on ${row.page_id}${row.comment ? `: ${row.comment}` : ""}`;
  const payload = { text, blocks, username: "fidbak", icon_emoji: ":speech_balloon:" };
  const channel = policy?.slackChannel || env.FIDBAK_SLACK_CHANNEL;
  if (channel)
    payload.channel = channel;
  await fetch(webhook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  }).then(async (r) => {
    const body = await r.text().catch(() => "");
    console.log("fidbak: slack response", r.status, body);
    if (!r.ok) {
      console.warn("fidbak: slack webhook non-2xx", r.status);
    }
  }).catch((e) => {
    console.warn("fidbak: slack webhook error", e?.message || e);
  });
}
__name(postSlack, "postSlack");

// ../../node_modules/.pnpm/wrangler@3.114.14/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../node_modules/.pnpm/wrangler@3.114.14/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-iNJs4b/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// ../../node_modules/.pnpm/wrangler@3.114.14/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-iNJs4b/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
__name(__Facade_ScheduledController__, "__Facade_ScheduledController__");
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = (request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    };
    #dispatcher = (type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    };
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
