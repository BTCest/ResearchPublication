// Cloudflare Worker — serves the static dashboard + a small API
// for password-gated admin writes, backed by a Google Sheet
// (via a Google service account, server-to-server, no signed-in user needed).
//
// Routes (unchanged contract, so index.html needs no changes):
//   POST /api/verify-admin   { password }              -> { ok: true|false }
//   GET  /api/admin-data                                -> shared admin overlay (public read)
//   POST /api/admin-data     (header X-Admin-Password)  -> save shared admin overlay (auth required)
//   *                                                    -> static assets (the dashboard itself)
//
// Storage model: the whole admin overlay (adminPubs, adminRoster, pubEdits,
// pubDeletes, rosterEdits, rosterDeletes) is kept as ONE JSON blob written into
// cell A1 of a tab called "AdminData" in a Google Sheet — same shape that used
// to live in KV, just relocated. This keeps the change small and low-risk.
//
// Required Cloudflare secrets (Settings -> Variables and Secrets):
//   ADMIN_PASSWORD              - the dashboard's admin password
//   GOOGLE_SERVICE_ACCOUNT_EMAIL - the service account's client_email
//   GOOGLE_PRIVATE_KEY           - the service account's private_key (PEM, with \n kept literal)
// Required Cloudflare variable (can be a plain var, not secret):
//   GOOGLE_SHEET_ID              - the spreadsheet ID from its URL

const EMPTY_DATA = {
  adminPubs: [],
  adminRoster: [],
  pubEdits: {},
  pubDeletes: [],
  rosterEdits: {},
  rosterDeletes: [],
};

const SHEET_TAB = 'AdminData';
const SHEET_RANGE = `${SHEET_TAB}!A1`;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

// ---------- base64url helpers ----------
function base64url(bytes) {
  let str = '';
  if (typeof bytes === 'string') {
    str = btoa(unescape(encodeURIComponent(bytes)));
  } else {
    let bin = '';
    const arr = new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    str = btoa(bin);
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const bin = atob(body);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---------- Google service-account auth (JWT bearer -> access token) ----------
let cachedToken = null; // { token, exp } — best-effort in-memory cache per isolate

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp - 60 > now) return cachedToken.token;

  const privateKeyPem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;

  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned)
  );
  const jwt = `${unsigned}.${base64url(signature)}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${encodeURIComponent(jwt)}`,
  });
  if (!res.ok) throw new Error('google token exchange failed: ' + (await res.text()));
  const data = await res.json();
  cachedToken = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

// ---------- Sheets read/write ----------
async function readSheetData(env) {
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(SHEET_RANGE)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error('sheets read failed: ' + (await res.text()));
  const data = await res.json();
  const cell = data.values && data.values[0] && data.values[0][0];
  if (!cell) return EMPTY_DATA;
  try { return JSON.parse(cell); } catch { return EMPTY_DATA; }
}

async function writeSheetData(env, obj) {
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(SHEET_RANGE)}?valueInputOption=RAW`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ range: SHEET_RANGE, values: [[JSON.stringify(obj)]] }),
  });
  if (!res.ok) throw new Error('sheets write failed: ' + (await res.text()));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/verify-admin' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const ok = !!env.ADMIN_PASSWORD && body.password === env.ADMIN_PASSWORD;
      return json({ ok }, ok ? 200 : 401);
    }

    if (url.pathname === '/api/admin-data' && request.method === 'GET') {
      try {
        const data = await readSheetData(env);
        return json(data);
      } catch (e) {
        return json({ ok: false, error: String(e) }, 500);
      }
    }

    if (url.pathname === '/api/admin-data' && request.method === 'POST') {
      const pw = request.headers.get('X-Admin-Password') || '';
      if (!env.ADMIN_PASSWORD || pw !== env.ADMIN_PASSWORD) {
        return json({ ok: false, error: 'unauthorized' }, 401);
      }
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, error: 'bad json' }, 400); }
      try {
        await writeSheetData(env, body);
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e) }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};
