'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { URL } = require('url');

const PORT = 4014;
const ANNOUNCE_MS = 24 * 60 * 60 * 1000; // 24 hours
const ROOT = __dirname;
const DIR_JSON = path.join(ROOT, 'itcdir.json');
const UPDATES_FILE = path.join(ROOT, 'itcdir.updates');
const WIU_ROOT = path.join(ROOT, 'wius');

/**
 * itcdir.json shape:
 * {
 *   "hostname": "this-server.example.com",   // optional; used in /api/serving announcements
 *   "wp": {
 *     "802123": { "servers":   [ { "host": "...", "zjpub": 4800 }, ... ] },
 *     "802999": { "referrals": [ { "host": "upstream.example.com" }, ... ] },
 *     "*":      { "referrals": [ { "host": "dir1.example.com" }, ... ] }
 *   }
 * }
 */
/** @type {{ hostname: string, wp: Record<string, { servers?: Array<{host:string, zjpub?:number}>, referrals?: Array<{host:string}> }> }} */
let dirData = { hostname: os.hostname(), wp: {} };

function loadDirData() {
  const raw = fs.readFileSync(DIR_JSON, 'utf8');
  const data = JSON.parse(raw);
  if (!data || typeof data !== 'object') {
    throw new Error('itcdir.json must be a JSON object');
  }

  // Support either { "wp": { ... } } or a flat map of wp keys at top level
  let wpMap = {};
  if (data.wp && typeof data.wp === 'object' && !Array.isArray(data.wp)) {
    wpMap = data.wp;
  } else {
    for (const [k, v] of Object.entries(data)) {
      if (k === 'hostname' || k === 'referral') continue;
      if (v && typeof v === 'object' && (v.servers || v.referrals)) wpMap[k] = v;
    }
  }

  const hostname =
    typeof data.hostname === 'string' && data.hostname.trim()
      ? data.hostname.trim()
      : os.hostname();

  dirData = { hostname, wp: wpMap };

  const keys = Object.keys(dirData.wp);
  const serving = keys.filter((k) => k !== '*' && Array.isArray(dirData.wp[k].servers));
  const refs = collectReferralHosts();
  console.log(
    `[itcdir] Loaded ${DIR_JSON}: hostname=${dirData.hostname}, ` +
      `${keys.length} wp keys (${serving.length} with servers), ` +
      `${refs.length} unique referral host(s)`
  );
  if (isLoopbackHost(dirData.hostname)) {
    console.warn(
      `[itcdir] WARNING: hostname="${dirData.hostname}" is loopback. ` +
        `Announcements will be skipped until you set "hostname" in itcdir.json ` +
        `to this machine's public DNS name or IP (not 127.0.0.1).`
    );
  }
}

function isLoopbackHost(host) {
  const h = String(host || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h === '0.0.0.0' ||
    h === '::'
  );
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

function sendText(res, status, text) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
  });
  res.end(text);
}

/** WP is rrrnnn — 6 digits (railroad + id). */
function normalizeWp(wp) {
  if (wp == null) return null;
  const s = String(wp).trim();
  if (!/^\d{6}$/.test(s)) return null;
  return s;
}

/**
 * Extract host strings from a referrals array.
 * Accepts: [ { "host": "x" }, ... ] or legacy [ "x", ... ]
 */
function referralHostsFrom(entry) {
  if (!entry || !Array.isArray(entry.referrals)) return [];
  const out = [];
  for (const item of entry.referrals) {
    if (typeof item === 'string' && item.trim()) out.push(item.trim());
    else if (item && typeof item === 'object' && item.host) out.push(String(item.host).trim());
  }
  return out.filter(Boolean);
}

/** All unique referral hosts mentioned anywhere in the directory. */
function collectReferralHosts() {
  const set = new Set();
  for (const entry of Object.values(dirData.wp)) {
    for (const h of referralHostsFrom(entry)) set.add(h);
  }
  return [...set];
}

/** WP ids this node publishes (entries with a non-empty servers list, not "*"). */
function listServedWps() {
  const wps = [];
  for (const [key, entry] of Object.entries(dirData.wp)) {
    if (key === '*') continue;
    if (entry && Array.isArray(entry.servers) && entry.servers.length > 0) wps.push(key);
  }
  return wps;
}

/**
 * True if wp already has this server host in its servers list in memory.
 */
/**
 * True if wp already lists this host under servers[] or referrals[] in itcdir.json.
 */
function isWpServerKnown(wp, serverHost) {
  const entry = dirData.wp[wp];
  if (!entry) return false;
  const want = String(serverHost).trim().toLowerCase();

  if (Array.isArray(entry.servers)) {
    for (const s of entry.servers) {
      if (s && s.host && String(s.host).trim().toLowerCase() === want) return true;
    }
  }
  for (const h of referralHostsFrom(entry)) {
    if (h.toLowerCase() === want) return true;
  }
  return false;
}

/**
 * One pasteable itcdir.json wp-object line, e.g.
 *   "802055":{"referrals":[{"host":"mark"}]},
 */
function formatUpdatesLine(wp, server) {
  const entry = { referrals: [{ host: server }] };
  return `${JSON.stringify(wp)}: ${JSON.stringify(entry)},\n`;
}

/** True if itcdir.updates already has this wp+server (pasteable or legacy form). */
function isAlreadyInUpdatesFile(wp, server) {
  try {
    const text = fs.readFileSync(UPDATES_FILE, 'utf8');
    const paste = formatUpdatesLine(wp, server).trim();
    if (text.includes(paste)) return true;
    // looser match: "802055" ... "mark" on same line
    for (const line of text.split(/\r?\n/)) {
      if (!line.includes(JSON.stringify(wp))) continue;
      if (line.includes(JSON.stringify(server)) || line.includes(`"host":"${server}"`)) {
        return true;
      }
    }
    // legacy JSON-lines form
    if (text.includes(`"wp":"${wp}"`) && text.includes(`"server":"${server}"`)) {
      // only if some line has both
      for (const line of text.split(/\r?\n/)) {
        if (line.includes(`"wp":"${wp}"`) && line.includes(`"server":"${server}"`)) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Parse newer=yyyymmddhhmmss as local time → Date, or null if invalid.
 */
function parseNewer(stamp) {
  if (stamp == null || stamp === '') return null;
  const s = String(stamp).trim();
  if (!/^\d{14}$/.test(s)) return null;
  const y = +s.slice(0, 4);
  const mo = +s.slice(4, 6) - 1;
  const d = +s.slice(6, 8);
  const h = +s.slice(8, 10);
  const mi = +s.slice(10, 12);
  const se = +s.slice(12, 14);
  const dt = new Date(y, mo, d, h, mi, se);
  if (
    dt.getFullYear() !== y ||
    dt.getMonth() !== mo ||
    dt.getDate() !== d ||
    dt.getHours() !== h ||
    dt.getMinutes() !== mi ||
    dt.getSeconds() !== se
  ) {
    return null;
  }
  return dt;
}

/**
 * Resolve find for a wp:
 *  1) exact entry with servers → { servers }
 *  2) exact entry with referrals → { referral: [hosts] }
 *  3) "*" entry with referrals (or servers) → same
 *  4) 400
 */
function handleFind(res, wpRaw) {
  const wp = normalizeWp(wpRaw);
  if (!wp) {
    return sendJson(res, 400, {
      error: "don't know",
      detail: 'missing or invalid wp (expected 6 digits rrrnnn)',
    });
  }

  const exact = dirData.wp[wp];
  if (exact) {
    if (Array.isArray(exact.servers) && exact.servers.length > 0) {
      return sendJson(res, 200, { servers: exact.servers });
    }
    const refs = referralHostsFrom(exact);
    if (refs.length > 0) {
      return sendJson(res, 200, { referral: refs });
    }
  }

  const star = dirData.wp['*'];
  if (star) {
    if (Array.isArray(star.servers) && star.servers.length > 0) {
      return sendJson(res, 200, { servers: star.servers });
    }
    const refs = referralHostsFrom(star);
    if (refs.length > 0) {
      return sendJson(res, 200, { referral: refs });
    }
  }

  return sendJson(res, 400, {
    error: "don't know",
    detail: `no servers or referrals for wp ${wp}`,
  });
}

function handleGet(res, wpRaw, newerRaw) {
  const wp = normalizeWp(wpRaw);
  if (!wp) {
    return sendJson(res, 400, {
      error: "don't know",
      detail: 'missing or invalid wp (expected 6 digits rrrnnn)',
    });
  }

  const rrr = wp.slice(0, 3);
  const filePath = path.join(WIU_ROOT, rrr, `${wp}.json`);

  const resolved = path.resolve(filePath);
  const wiuRootResolved = path.resolve(WIU_ROOT);
  if (!resolved.startsWith(wiuRootResolved + path.sep) && resolved !== wiuRootResolved) {
    return sendJson(res, 400, { error: "don't know", detail: 'invalid path' });
  }

  let st;
  try {
    st = fs.statSync(resolved);
  } catch {
    return sendJson(res, 404, { error: 'not found', detail: `no file wiu/${rrr}/${wp}.json` });
  }
  if (!st.isFile()) {
    return sendJson(res, 404, { error: 'not found', detail: `no file wiu/${rrr}/${wp}.json` });
  }

  if (newerRaw != null && newerRaw !== '') {
    const newer = parseNewer(newerRaw);
    if (!newer) {
      return sendJson(res, 400, {
        error: "don't know",
        detail: 'invalid newer= (expected yyyymmddhhmmss)',
      });
    }
    if (st.mtime.getTime() <= newer.getTime()) {
      return sendJson(res, 404, {
        error: 'not newer',
        detail: `file not newer than ${newerRaw}`,
      });
    }
  }

  let body;
  try {
    body = fs.readFileSync(resolved, 'utf8');
  } catch {
    return sendJson(res, 500, { error: 'read failed' });
  }

  try {
    JSON.parse(body);
  } catch {
    return sendJson(res, 500, { error: 'invalid json file' });
  }

  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'Last-Modified': st.mtime.toUTCString(),
  });
  res.end(body);
}

/**
 * POST /api/serving?wp=rrrnnn&server=hostname
 * If this wp+server is not already in itcdir.json (servers or referrals),
 * append a pasteable wp line to itcdir.updates (same shape as itcdir.json entries).
 */
function handleServing(res, wpRaw, serverRaw, fromAddr) {
  const from = fromAddr || '?';
  const wp = normalizeWp(wpRaw);
  const server = serverRaw != null ? String(serverRaw).trim() : '';
  if (!wp || !server) {
    console.log(`[itcdir] serving from ${from}: bad request wp=${wpRaw} server=${serverRaw}`);
    return sendJson(res, 400, {
      error: "don't know",
      detail: 'need wp=rrrnnn and server=hostname',
    });
  }

  if (isWpServerKnown(wp, server)) {
    console.log(
      `[itcdir] serving from ${from}: wp=${wp} server=${server} → known ` +
        `(already in itcdir.json servers[] or referrals[]; no update written)`
    );
    return sendJson(res, 200, { status: 'known', wp, server });
  }

  if (isLoopbackHost(server)) {
    console.log(
      `[itcdir] serving from ${from}: wp=${wp} server=${server} → ignored ` +
        `(loopback server name is not useful for peer directory updates)`
    );
    return sendJson(res, 200, {
      status: 'ignored',
      wp,
      server,
      detail: 'loopback server identity rejected',
    });
  }

  if (isAlreadyInUpdatesFile(wp, server)) {
    console.log(
      `[itcdir] serving from ${from}: wp=${wp} server=${server} → known ` +
        `(already pending in itcdir.updates)`
    );
    return sendJson(res, 200, { status: 'known', wp, server, detail: 'already in updates file' });
  }

  // Pasteable into the "wp" object of itcdir.json
  const line = formatUpdatesLine(wp, server);

  try {
    fs.appendFileSync(UPDATES_FILE, line, 'utf8');
  } catch (err) {
    console.error('[itcdir] Failed to write itcdir.updates:', err.message);
    return sendJson(res, 500, { error: 'failed to write updates file' });
  }

  console.log(
    `[itcdir] serving from ${from}: wp=${wp} server=${server} → recorded → ${UPDATES_FILE}`
  );
  console.log(`[itcdir]   ${line.trim()}`);
  return sendJson(res, 200, { status: 'recorded', wp, server });
}

/**
 * POST /api/serving?... on a remote referral host.
 * @returns {Promise<{ host: string, ok: boolean, detail: string }>}
 */
function postServing(remoteHost, wp, serverHostname) {
  return new Promise((resolve) => {
    const pathQuery =
      `/api/serving?wp=${encodeURIComponent(wp)}` +
      `&server=${encodeURIComponent(serverHostname)}`;
    const opts = {
      hostname: remoteHost,
      port: PORT,
      path: pathQuery,
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Length': 0,
      },
      timeout: 15000,
    };

    const req = http.request(opts, (resp) => {
      let body = '';
      resp.on('data', (c) => (body += c));
      resp.on('end', () => {
        resolve({
          host: remoteHost,
          ok: resp.statusCode >= 200 && resp.statusCode < 300,
          detail: `HTTP ${resp.statusCode} ${body.slice(0, 200)}`,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ host: remoteHost, ok: false, detail: 'timeout' });
    });
    req.on('error', (err) => {
      resolve({ host: remoteHost, ok: false, detail: err.message });
    });
    req.end();
  });
}

/**
 * Announce every WP we serve to every referral host (except ourselves).
 * server= is this node's public "hostname" from itcdir.json — must not be loopback.
 */
async function announceServing() {
  const wps = listServedWps();
  const selfName = dirData.hostname;

  if (isLoopbackHost(selfName)) {
    console.warn(
      `[itcdir] Announce: SKIPPED — hostname is "${selfName}". ` +
        `Set itcdir.json "hostname" to your public IP/DNS name so peers can record you.`
    );
    return;
  }

  const remotes = collectReferralHosts().filter((h) => {
    const lower = h.toLowerCase();
    const self = selfName.toLowerCase();
    return lower !== self && !isLoopbackHost(h);
  });

  if (wps.length === 0) {
    console.log('[itcdir] Announce: no local WPs with servers; skip');
    return;
  }
  if (remotes.length === 0) {
    console.log('[itcdir] Announce: no referral hosts to notify; skip');
    return;
  }

  console.log(
    `[itcdir] Announce: ${wps.length} wp(s) → ${remotes.length} referral host(s) as server=${selfName}`
  );

  for (const remote of remotes) {
    for (const wp of wps) {
      const result = await postServing(remote, wp, selfName);
      if (result.ok) {
        console.log(`[itcdir]   OK  ${remote} wp=${wp}: ${result.detail}`);
      } else {
        console.log(`[itcdir]   FAIL ${remote} wp=${wp}: ${result.detail}`);
      }
    }
  }
}

const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  } catch {
    return sendJson(res, 400, { error: "don't know", detail: 'bad request url' });
  }

  const pathname = url.pathname.replace(/\/+$/, '') || '/';
  const method = req.method || 'GET';

  if (pathname === '/api/serving' && method === 'POST') {
    const from =
      (req.headers['x-forwarded-for'] && String(req.headers['x-forwarded-for']).split(',')[0].trim()) ||
      (req.socket && req.socket.remoteAddress) ||
      '?';
    return handleServing(
      res,
      url.searchParams.get('wp'),
      url.searchParams.get('server'),
      from
    );
  }

  if (method !== 'GET') {
    return sendText(res, 405, 'Method Not Allowed');
  }

  if (pathname === '/api/find') {
    return handleFind(res, url.searchParams.get('wp'));
  }
  if (pathname === '/api/get') {
    return handleGet(res, url.searchParams.get('wp'), url.searchParams.get('newer'));
  }
  if (pathname === '/health' || pathname === '/') {
    return sendJson(res, 200, {
      ok: true,
      service: 'itcdir',
      port: PORT,
      hostname: dirData.hostname,
    });
  }

  return sendJson(res, 404, { error: 'not found' });
});

try {
  loadDirData();
} catch (err) {
  console.error(`[itcdir] Failed to load ${DIR_JSON}:`, err.message);
  process.exit(1);
}

try {
  process.on('SIGHUP', () => {
    try {
      loadDirData();
    } catch (err) {
      console.error('[itcdir] Reload failed:', err.message);
    }
  });
} catch {
  /* Windows may not support SIGHUP */
}

server.listen(PORT, () => {
  console.log(`[itcdir] REST API listening on http://0.0.0.0:${PORT}`);
  console.log(`[itcdir]   GET  /api/find?wp=rrrnnn`);
  console.log(`[itcdir]   GET  /api/get?wp=rrrnnn[&newer=yyyymmddhhmmss]`);
  console.log(`[itcdir]   POST /api/serving?wp=rrrnnn&server=hostname`);

  // Startup announce, then every 24 hours
  announceServing().catch((err) => console.error('[itcdir] Announce error:', err));
  setInterval(() => {
    try {
      loadDirData(); // pick up manual json edits before each cycle
    } catch (err) {
      console.error('[itcdir] Reload before announce failed:', err.message);
    }
    announceServing().catch((err) => console.error('[itcdir] Announce error:', err));
  }, ANNOUNCE_MS);
});
