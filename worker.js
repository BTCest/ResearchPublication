// Cloudflare Worker — serves the static dashboard + a small API
// for password-gated admin writes, backed by Workers KV.
//
// Routes:
//   POST /api/verify-admin   { password }              -> { ok: true|false }
//   GET  /api/admin-data                                -> shared admin overlay (public read)
//   POST /api/admin-data     (header X-Admin-Password)  -> save shared admin overlay (auth required)
//   *                                                    -> static assets (the dashboard itself)

const KV_KEY = 'admin-data';

const EMPTY_DATA = {
  adminPubs: [],
  adminRoster: [],
  pubEdits: {},
  pubDeletes: [],
  rosterEdits: {},
  rosterDeletes: [],
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- verify password, no data returned either way ---
    if (url.pathname === '/api/verify-admin' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const ok = !!env.ADMIN_PASSWORD && body.password === env.ADMIN_PASSWORD;
      return json({ ok }, ok ? 200 : 401);
    }

    // --- read shared admin-added / edited / deleted records (public, no auth) ---
    if (url.pathname === '/api/admin-data' && request.method === 'GET') {
      const raw = await env.DASHBOARD_KV.get(KV_KEY);
      return json(raw ? JSON.parse(raw) : EMPTY_DATA);
    }

    // --- write shared admin data (requires correct password header) ---
    if (url.pathname === '/api/admin-data' && request.method === 'POST') {
      const pw = request.headers.get('X-Admin-Password') || '';
      if (!env.ADMIN_PASSWORD || pw !== env.ADMIN_PASSWORD) {
        return json({ ok: false, error: 'unauthorized' }, 401);
      }
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
      await env.DASHBOARD_KV.put(KV_KEY, JSON.stringify(body));
      return json({ ok: true });
    }

    // --- everything else: serve the static dashboard files ---
    return env.ASSETS.fetch(request);
  },
};
