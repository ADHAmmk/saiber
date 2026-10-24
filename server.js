'use strict';
// ADHAM GLOBAL CONTROL - zero-dependency server. Run: node server.js
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path'),
  crypto = require('crypto'), readline = require('readline');
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
const DB = path.join(__dirname, 'data.json');
// Set ADHAM_PASS in the environment to rotate the password at startup, or leave it empty to use the stored hash.
const FIXED_PASSWORD = process.env.ADHAM_PASS || '';
// OPEN_MODE: no login screen while the server only listens on this computer (127.0.0.1). Set env OPEN_MODE=0 to bring the login back.
const OPEN_MODE = HOST === '127.0.0.1' && process.env.OPEN_MODE !== '0';
let db = {
  pass: null, events: [], sites: [
    ['Adham Web Studio', 'https://technological-adham.vercel.app/'],
    ['El-Sadat School', 'https://el-sadat-school.vercel.app/'],
    ['Sunbulawin Education Portal', 'https://al-edara-esnblawen.vercel.app/']
  ].map(([name, url], i) => ({ id: 's' + i, name, url, hist: [] }))
};
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB, 'utf8'))); } catch {}
const save = () => fs.writeFileSync(DB, JSON.stringify(db, null, 1));
const hash = (p, s = crypto.randomBytes(16).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 64).toString('hex');
const verify = (p, h) => { const [s, k] = h.split(':'), a = crypto.scryptSync(p, s, 64), b = Buffer.from(k, 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const ev = (msg, lvl = 'info') => { db.events.unshift({ t: Date.now(), msg, lvl }); db.events = db.events.slice(0, 100); };

/* ---------- real probes ---------- */
function probe(url) {
  return new Promise(res => {
    const u = new URL(url), t0 = Date.now(); let done = false;
    const fin = r => { if (!done) { done = true; res(r); } };
    const rq = (u.protocol === 'https:' ? https : http).request(u, { method: 'GET', timeout: 10000, headers: { 'user-agent': 'AdhamGlobalControl/1.0' } }, r => {
      let ssl = null; const c = r.socket.getPeerCertificate && r.socket.getPeerCertificate();
      if (c && c.valid_to) ssl = Math.floor((new Date(c.valid_to) - Date.now()) / 864e5);
      r.resume(); fin({ ok: r.statusCode < 500, code: r.statusCode, ms: Date.now() - t0, ssl, ip: r.socket.remoteAddress });
    });
    rq.on('timeout', () => { rq.destroy(); fin({ ok: false, code: 0, ms: Date.now() - t0, err: 'TIMEOUT' }); });
    rq.on('error', e => fin({ ok: false, code: 0, ms: Date.now() - t0, err: e.code || 'ERROR' }));
    rq.end();
  });
}
const geoCache = {};
function geo(ip) {
  ip = (ip || '').replace('::ffff:', '');
  if (!ip) return Promise.resolve(null);
  if (ip in geoCache) return Promise.resolve(geoCache[ip]);
  return new Promise(res => {
    const rq = http.get('http://ip-api.com/json/' + ip + '?fields=status,lat,lon,country,city', r => {
      let b = ''; r.on('data', d => b += d);
      r.on('end', () => { try { const j = JSON.parse(b); geoCache[ip] = j.status === 'success' ? j : null; } catch { geoCache[ip] = null; } res(geoCache[ip]); });
    });
    rq.on('error', () => res(null)); rq.setTimeout(4000, () => { rq.destroy(); res(null); });
  });
}
async function check(s) {
  const r = await probe(s.url), prev = s.state;
  s.state = { ...r, t: Date.now() };
  if (r.ip && !s.geo) s.geo = await geo(r.ip);
  s.hist = (s.hist || []).concat({ t: Date.now(), ok: r.ok, ms: r.ms }).slice(-60);
  if (prev && prev.ok !== r.ok) ev(r.ok ? s.name + ' is BACK ONLINE' : s.name + ' is DOWN (' + (r.code || r.err) + ')', r.ok ? 'ok' : 'bad');
  if (r.ssl !== null && r.ssl < 14 && r.ssl >= 0) ev('SSL for ' + s.name + ' expires in ' + r.ssl + ' days', 'warn');
}
const scanAll = async () => { await Promise.all(db.sites.map(check)); save(); };

/* ---------- http ---------- */
const sessions = new Map(), tries = new Map();
const cookies = r => Object.fromEntries((r.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]));
const authed = r => OPEN_MODE || (sessions.get(cookies(r).sid) || 0) > Date.now();
const send = (res, c, o) => { res.writeHead(c, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };
const readBody = r => new Promise(ok => { let b = ''; r.on('data', d => { b += d; if (b.length > 1e4) r.destroy(); }); r.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch { ok({}); } }); });
const page = (res, f) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(fs.readFileSync(path.join(__dirname, f))); };
const pub = s => { const { token, ...r } = s; return { ...r, hasToken: !!token }; };
const state = () => ({ sites: db.sites.map(pub), events: db.events.slice(0, 40) });
const ghf = (b, s) => {
  const repo = String(b.repo || '').trim();
  if (repo && !/^[\w.-]+\/[\w.-]+$/.test(repo)) return 'Repo must look like owner/name';
  s.repo = repo; s.branch = String(b.branch || 'main').trim().slice(0, 80) || 'main';
  if (b.token) s.token = String(b.token).trim();
  return null;
};
const enc = p => p.split('/').map(encodeURIComponent).join('/');
const okPath = p => typeof p === 'string' && p && !p.startsWith('/') && !p.includes('..') && p.length < 300;
function gh(s, method, p, body) {
  return new Promise(res => {
    if (!s.repo || !s.token) return res({ status: 400, json: { message: 'Connect GitHub repo + token first (EDIT the target).' } });
    const data = body ? JSON.stringify(body) : null;
    const rq = https.request({ hostname: 'api.github.com', path: '/repos/' + s.repo + p, method, timeout: 15000,
      headers: { authorization: 'Bearer ' + s.token, 'user-agent': 'AdhamGlobalControl', accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', ...(data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {}) } }, r => {
      let b = ''; r.on('data', d => b += d);
      r.on('end', () => { let j = {}; try { j = JSON.parse(b); } catch {} res({ status: r.statusCode, json: j }); });
    });
    rq.on('timeout', () => { rq.destroy(); res({ status: 504, json: { message: 'GitHub timeout' } }); });
    rq.on('error', e => res({ status: 502, json: { message: e.code || 'network error' } }));
    if (data) rq.write(data); rq.end();
  });
}
const cleanUrl = u => { try { const x = new URL(String(u).trim()); return /^https?:$/.test(x.protocol) ? x.href : null; } catch { return null; } };

const server = http.createServer(async (req, res) => {
  res.setHeader('x-frame-options', 'DENY'); res.setHeader('x-content-type-options', 'nosniff'); res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('content-security-policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:");
  const url = req.url.split('?')[0], ip = req.socket.remoteAddress;
  if (OPEN_MODE && !/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host || '')) { res.writeHead(403); return res.end('Forbidden'); }
  if (req.method === 'GET' && url === '/login') { if (OPEN_MODE) { res.writeHead(302, { location: '/' }); return res.end(); } return page(res, 'login.html'); }
  if (req.method === 'GET' && url === '/dashboard') { if (authed(req)) return page(res, 'dashboard.html'); res.writeHead(302, { location: '/login' }); return res.end(); }
  if (req.method === 'GET' && url === '/') { if (authed(req)) return page(res, 'app.html'); res.writeHead(302, { location: '/login' }); return res.end(); }
  if (url === '/api/login' && req.method === 'POST') {
    const t = tries.get(ip) || { n: 0, until: 0 };
    if (t.until > Date.now()) return send(res, 429, { error: 'LOCKED. TRY LATER.' });
    const b = await readBody(req); await new Promise(r => setTimeout(r, 400));
    if (typeof b.password === 'string' && verify(b.password.trim(), db.pass)) {
      tries.delete(ip); const sid = crypto.randomBytes(32).toString('hex'); sessions.set(sid, Date.now() + 8 * 36e5);
      res.setHeader('set-cookie', 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800');
      return send(res, 200, { ok: true });
    }
    t.n++; if (t.n >= 5) { t.until = Date.now() + 6e5; t.n = 0; } tries.set(ip, t);
    return send(res, 401, { error: 'ACCESS DENIED' });
  }
  if (!url.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }
  if (!authed(req)) return send(res, 401, { error: 'unauthorized' });
  if (req.method !== 'GET' && !(req.headers['content-type'] || '').includes('application/json')) return send(res, 415, { error: 'json only' });
  const parts = url.split('/').filter(Boolean), id = parts[2];
  if (url === '/api/state') return send(res, 200, state());
  if (url === '/api/logout') { sessions.delete(cookies(req).sid); return send(res, 200, { ok: true }); }
  if (url === '/api/scan') { await scanAll(); return send(res, 200, state()); }
  if (parts[1] === 'sites' && parts[3]) {
    const s = db.sites.find(x => x.id === id); if (!s) return send(res, 404, { error: 'not found' });
    const q = new URL(req.url, 'http://x').searchParams, br = '?ref=' + encodeURIComponent(s.branch || 'main'), bn = s.branch || 'main';
    const fail = r => send(res, r.status === 401 || r.status === 403 ? 403 : r.status || 500, { error: (r.json && r.json.message) || 'GitHub error' });
    if (parts[3] === 'tree' && req.method === 'GET') {
      const r = await gh(s, 'GET', '/git/trees/' + encodeURIComponent(bn) + '?recursive=1'); if (r.status !== 200) return fail(r);
      return send(res, 200, { files: (r.json.tree || []).filter(t => t.type === 'blob' && !/(^|\/)(node_modules|\.git)\//.test(t.path)).slice(0, 3000).map(t => ({ path: t.path, size: t.size })) });
    }
    if (parts[3] === 'file') {
      if (req.method === 'GET') {
        const p = q.get('path'); if (!okPath(p)) return send(res, 400, { error: 'bad path' });
        const r = await gh(s, 'GET', '/contents/' + enc(p) + br);
        if (r.status !== 200) return fail(r);
        if (Array.isArray(r.json)) return send(res, 400, { error: 'Not a file' });
        const buf = r.json.content ? Buffer.from(r.json.content, 'base64') : null;
        if (!buf || buf.includes(0)) return send(res, 200, { binary: true, sha: r.json.sha, size: r.json.size });
        return send(res, 200, { content: buf.toString('utf8'), sha: r.json.sha });
      }
      const b = await readBody(req); if (!okPath(b.path)) return send(res, 400, { error: 'bad path' });
      const msg = String(b.message || '').trim().slice(0, 200);
      if (req.method === 'PUT') {
        if (typeof b.content !== 'string') return send(res, 400, { error: 'content required' });
        const r = await gh(s, 'PUT', '/contents/' + enc(b.path), { message: msg || 'Update ' + b.path + ' via Adham Global Control', content: Buffer.from(b.content, 'utf8').toString('base64'), branch: bn, ...(b.sha ? { sha: b.sha } : {}) });
        if (r.status !== 200 && r.status !== 201) return fail(r);
        ev('Committed ' + b.path + ' -> ' + s.name, 'ok'); save(); return send(res, 200, { sha: r.json.content.sha });
      }
      if (req.method === 'DELETE') {
        const r = await gh(s, 'DELETE', '/contents/' + enc(b.path), { message: msg || 'Delete ' + b.path + ' via Adham Global Control', sha: b.sha, branch: bn });
        if (r.status !== 200) return fail(r);
        ev('Deleted ' + b.path + ' <- ' + s.name, 'warn'); save(); return send(res, 200, { ok: true });
      }
    }
    return send(res, 404, { error: 'not found' });
  }
  if (parts[1] === 'sites') {
    if (req.method === 'POST' && !id) {
      const b = await readBody(req), u = cleanUrl(b.url), name = String(b.name || '').trim().slice(0, 60);
      if (!u || !name) return send(res, 400, { error: 'Name and valid http(s) URL required' });
      const s = { id: 's' + Date.now().toString(36), name, url: u, hist: [] }; const ge = ghf(b, s); if (ge) return send(res, 400, { error: ge }); db.sites.push(s); ev('Target added: ' + name); await check(s); save(); return send(res, 200, state());
    }
    const s = db.sites.find(x => x.id === id); if (!s) return send(res, 404, { error: 'not found' });
    if (req.method === 'PUT') {
      const b = await readBody(req), u = cleanUrl(b.url), name = String(b.name || '').trim().slice(0, 60);
      if (!u || !name) return send(res, 400, { error: 'Name and valid http(s) URL required' });
      const ge = ghf(b, s); if (ge) return send(res, 400, { error: ge }); if (u !== s.url) { s.geo = null; s.hist = []; } s.name = name; s.url = u; ev('Target updated: ' + name); await check(s); save(); return send(res, 200, state());
    }
    if (req.method === 'DELETE') { db.sites = db.sites.filter(x => x !== s); ev('Target removed: ' + s.name, 'warn'); save(); return send(res, 200, state()); }
  }
  send(res, 404, { error: 'not found' });
}).on('error', e => { console.error(e.message); process.exit(1); });

/* ---------- boot ---------- */
function ask(q) { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); return new Promise(r => rl.question(q, a => { rl.close(); r(a); })); }
(async () => {
  if (process.argv.includes('--reset-pass')) db.pass = null;
  if (FIXED_PASSWORD) { db.pass = hash(FIXED_PASSWORD); save(); }
  if (!db.pass) {
    let p = process.env.ADHAM_PASS || '';
    while (p.length < 10) { p = await ask('Set a NEW admin password (min 10 chars): '); if (p.length < 10) console.log('Too short.'); }
    db.pass = hash(p); ev('Admin password set'); save(); sessions.clear();
  }
  server.listen(PORT, HOST, () => console.log('\n  ADHAM GLOBAL CONTROL online -> http://' + (HOST === '127.0.0.1' ? 'localhost' : HOST) + ':' + PORT + '\n'));
  await scanAll(); setInterval(scanAll, 60000);
})();
