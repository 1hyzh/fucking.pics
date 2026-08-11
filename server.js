const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAIN_PORT = Number(process.env.MAIN_PORT || 3000);
const FILES_PORT = Number(process.env.FILES_PORT || 3001);
const ROOT = __dirname;
const STORE = path.join(ROOT, 'data.json');
const UPLOADS = path.join(ROOT, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

function readDb() { try { return JSON.parse(fs.readFileSync(STORE)); } catch { return { users: [], media: [] }; } }
function writeDb(db) { fs.writeFileSync(STORE, JSON.stringify(db, null, 2)); }
function id(bytes = 18) { return crypto.randomBytes(bytes).toString('base64url'); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(x => x.trim().split('='))); }
const sessions = new Map();
function currentUser(req) { const s = sessions.get(parseCookies(req).session); return s || null; }
function send(res, code, body, type = 'application/json') { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(type === 'application/json' ? JSON.stringify(body) : body); }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
function mediaPage(item, url) {
  const rawUrl = `${url}?raw=1`;
  const title = escapeHtml(item.originalName || 'Temporary media');
  if (item.allowEmbeds === false) {
    return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{margin:0;background:#0b0b0e;color:#f4f4f5;font:16px system-ui;min-height:100vh;display:grid;place-items:center}main{max-width:560px;padding:24px;text-align:center}a{color:#dfff00}p{color:#a1a1aa;font-size:13px}</style><main><h1>${title}</h1><p>Embedding is disabled for this temporary media.</p><p><a href="${rawUrl}">Open media</a> · expires ${escapeHtml(new Date(item.expiresAt).toLocaleString())}</p></main></html>`;
  }
  const isImage = item.type.startsWith('image/');
  const tags = isImage
    ? `<meta property="og:image" content="${rawUrl}"><meta property="og:image:type" content="${item.type}"><meta name="twitter:card" content="summary_large_image">`
    : `<meta property="og:video" content="${rawUrl}"><meta property="og:video:secure_url" content="${rawUrl}"><meta property="og:video:type" content="${item.type}"><meta name="twitter:card" content="player">`;
  const player = isImage ? `<img src="${rawUrl}" alt="${title}">` : `<video src="${rawUrl}" controls autoplay muted playsinline></video>`;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><meta property="og:title" content="${title}"><meta property="og:site_name" content="fucking.pics"><meta property="og:url" content="${url}">${tags}<style>body{margin:0;background:#0b0b0e;color:#f4f4f5;font:16px system-ui;min-height:100vh;display:grid;place-items:center}main{max-width:min(100%,1100px);padding:24px;text-align:center}img,video{max-width:100%;max-height:82vh;border-radius:12px}p{color:#a1a1aa;font-size:13px}</style><main>${player}<p>Temporary media · expires ${escapeHtml(new Date(item.expiresAt).toLocaleString())}</p></main></html>`;
}
function body(req) { return new Promise((resolve, reject) => { let data = Buffer.alloc(0); req.on('data', c => { data = Buffer.concat([data, c]); if (data.length > 55 * 1024 * 1024) reject(new Error('Upload too large')); }); req.on('end', () => resolve(data)); req.on('error', reject); }); }
function cleanup(db) { const now = Date.now(); db.media = db.media.filter(m => { if (m.expiresAt > now) return true; try { fs.unlinkSync(path.join(UPLOADS, m.file)); } catch {} return false; }); writeDb(db); }

async function api(req, res, url) {
  const db = readDb(); cleanup(db);
  const user = currentUser(req);
  if (req.method === 'POST' && url.pathname === '/api/register') {
    const { email, password } = JSON.parse((await body(req)).toString());
    if (!email || !password || password.length < 8) return send(res, 400, { error: 'Use an email and a password of at least 8 characters.' });
    if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) return send(res, 409, { error: 'That email is already registered.' });
    const isFirstUser = db.users.length === 0;
    db.users.push({ id: id(), email, password: crypto.createHash('sha256').update(password).digest('hex'), approved: isFirstUser, admin: isFirstUser, createdAt: Date.now() }); writeDb(db);
    return send(res, 201, { message: isFirstUser ? 'Your admin account is ready. You can sign in now.' : 'Request sent. An admin must approve your account.' });
  }
  if (req.method === 'POST' && url.pathname === '/api/login') {
    const { email, password } = JSON.parse((await body(req)).toString());
    const u = db.users.find(x => x.email.toLowerCase() === String(email).toLowerCase());
    if (!u || u.password !== crypto.createHash('sha256').update(password).digest('hex')) return send(res, 401, { error: 'Incorrect email or password.' });
    if (!u.approved) return send(res, 403, { error: 'Your account is waiting for admin approval.' });
    const token = id(24); sessions.set(token, u); res.setHeader('Set-Cookie', `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`); return send(res, 200, { user: { email: u.email, admin: !!u.admin } });
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') { sessions.delete(parseCookies(req).session); res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0'); return send(res, 200, { ok: true }); }
  if (req.method === 'GET' && url.pathname === '/api/me') return send(res, 200, { user: user && { email: user.email, admin: !!user.admin } });
  if (req.method === 'GET' && url.pathname === '/api/media') { if (!user) return send(res, 401, { error: 'Sign in required.' }); return send(res, 200, { media: db.media.filter(m => m.userId === user.id || user.admin) }); }
  if (req.method === 'GET' && url.pathname === '/api/pending') { if (!user?.admin) return send(res, 403, { error: 'Admin only.' }); return send(res, 200, { users: db.users.filter(u => !u.approved) }); }
  if (req.method === 'POST' && url.pathname.startsWith('/api/approve/')) { if (!user?.admin) return send(res, 403, { error: 'Admin only.' }); const u = db.users.find(x => x.id === url.pathname.split('/').pop()); if (!u) return send(res, 404, { error: 'Not found.' }); u.approved = true; writeDb(db); return send(res, 200, { ok: true }); }
  if (req.method === 'POST' && url.pathname === '/api/upload') {
    if (!user) return send(res, 401, { error: 'Sign in required.' });
    const name = decodeURIComponent(req.headers['x-file-name'] || 'upload.bin').replace(/[^a-zA-Z0-9._-]/g, '_');
    const type = req.headers['content-type'] || 'application/octet-stream'; if (!/^image\/|^video\//.test(type)) return send(res, 415, { error: 'Only images and videos are allowed.' });
    const ttlMinutes = Math.min(Math.max(Number(req.headers['x-ttl-minutes'] || 1440), 10), 1440); const ext = path.extname(name).toLowerCase() || (type.startsWith('image/') ? '.jpg' : '.mp4'); const key = id(6); const file = `${key}${ext}`;
    const allowEmbeds = req.headers['x-allow-embeds'] !== 'false';
    fs.writeFileSync(path.join(UPLOADS, file), await body(req)); const item = { id: key, file, originalName: name, type, userId: user.id, allowEmbeds, createdAt: Date.now(), expiresAt: Date.now() + ttlMinutes * 60000 };
    db.media.push(item); writeDb(db); const host = `actual.${req.headers.host?.replace(/^actual\./, '') || 'fucking.pics'}`; const protocol = req.headers['x-forwarded-proto'] || 'http'; return send(res, 201, { item, url: `${protocol}://${host}/${file}` });
  }
  return false;
}

const app = fs.readFileSync(path.join(ROOT, 'main_page', 'index.html'));
const gallery = fs.readFileSync(path.join(ROOT, 'pics', 'index.html'));
const mainServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) { const out = await api(req, res, url); if (out === false) send(res, 404, { error: 'Not found.' }); return; }
    send(res, 200, app, 'text/html; charset=utf-8');
  } catch (e) { send(res, 400, { error: e.message || 'Bad request' }); }
});
const filesServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (/^\/[A-Za-z0-9_-]+\.[A-Za-z0-9]+$/.test(url.pathname)) {
    const db = readDb(); cleanup(db);
    const item = db.media.find(m => `/${m.file}` === url.pathname && m.expiresAt > Date.now());
    if (!item) return send(res, 404, 'Expired or missing', 'text/plain');
    if (item.allowEmbeds === false) {
      res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
      res.setHeader('X-Frame-Options', 'DENY');
    }
    if (url.searchParams.get('raw') === '1') {
      const filePath = path.join(UPLOADS, item.file);
      let size;
      try { size = fs.statSync(filePath).size; } catch { return send(res, 404, 'Missing', 'text/plain'); }
      res.writeHead(200, { 'Content-Type': item.type, 'Content-Length': size, 'Cache-Control': 'public, max-age=300', ...(item.allowEmbeds === false ? { 'Cross-Origin-Resource-Policy': 'same-origin' } : {}) });
      return fs.createReadStream(filePath).on('error', () => res.destroy()).pipe(res);
    }
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const publicUrl = `${protocol}://${req.headers.host}${url.pathname}`;
    return send(res, 200, mediaPage(item, publicUrl), 'text/html; charset=utf-8');
  }
  send(res, 200, gallery, 'text/html; charset=utf-8');
});
mainServer.listen(MAIN_PORT, () => console.log(`main app listening on :${MAIN_PORT}`));
filesServer.listen(FILES_PORT, () => console.log(`media service listening on :${FILES_PORT}`));
