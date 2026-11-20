'use strict';

// Dit: a Handshake resolver for your home network, on Umbrel.
// This server is the app's web UI and API. It also runs hnsd (lib/hnsd.js).
// The DNS front end your devices talk to is the separate "dns" service (dns-runner.js).
const {execFile} = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const {domainToASCII} = require('url');

const hnsd = require('./lib/hnsd');
const source = require('./lib/source');
const state = require('./lib/state');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_JSON = 16 * 1024;
const LOOKUP_TYPES = ['A', 'AAAA', 'NS', 'TXT', 'TLSA', 'CNAME', 'MX', 'DS'];
// The dns service refreshes its state file every 10s
const DNS_STATE_MAX_AGE = 30000;

class UserError extends Error {}

// ---------- validation ----------

// Labels may start with "_" for names like _443._tcp.mysite (TLSA)
const LABEL = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?';
const NAME_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);

// Accepts "mysite", "MySite.", "www.mysite/" or an emoji/Unicode name (converted to punycode).
function normalizeName(input) {
  const cleaned = String(input || '').trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  const ascii = cleaned.split('.').map(label => (label.startsWith('_') ? label : domainToASCII(label))).join('.');
  if (!ascii || ascii.length > 253 || !NAME_RE.test(ascii)) {
    throw new UserError('That is not a valid name. Use letters, digits and hyphens, like "mysite" or "www.mysite".');
  }
  return ascii;
}

// ---------- API ----------

async function getStatus() {
  const dns = state.loadDnsState();
  const fresh = !!dns && Date.now() - Date.parse(dns.updatedAt) < DNS_STATE_MAX_AGE;
  const dane = state.loadDaneState();
  const daneFresh = !!dane && Date.now() - Date.parse(dane.updatedAt) < DNS_STATE_MAX_AGE;
  return {
    version: require('./package.json').version,
    settings: state.loadSettings(),
    hnsd: await hnsd.status(),
    // null: the dns service has not reported (yet), or stopped reporting
    dns: fresh ? dns : null,
    // null: the DANE proxy has not reported (yet), or stopped reporting
    dane: daneFresh ? dane : null,
    // Tree roots collected from hnsd, for the Stateless DANE checker
    treeRoots: hnsd.treeRoots.summary(),
  };
}

// ---------- Stateless DANE checker (beta) ----------

// The Go checker, in this same image (docker/dane/check.go)
const DANE_BIN = process.env.DIT_DANE_BIN || '/usr/local/bin/dit-dane';
let checkRunning = false;

function runChecker(name) {
  return new Promise((resolve, reject) => {
    execFile(DANE_BIN, ['check', '-name', name, '-roots', hnsd.treeRoots.file],
      {timeout: 45000, maxBuffer: 256 * 1024},
      (err, stdout) => {
        // Exit code 1 only means "not verified": the report is still on stdout
        try {
          resolve(JSON.parse(stdout));
        } catch (e) {
          reject(new UserError(err && err.killed ? 'The check took too long.' : 'The checker did not answer.'));
        }
      });
  });
}

const tlsaKey = text => String(text).trim().toLowerCase().replace(/\s+/g, ' ');

// Checks a name's HIP-17 proofs, then compares the proven TLSA records with
// what Dit's own resolver (hnsd) answers right now
async function saneCheck(body) {
  const name = normalizeName(body.name);
  if (name.startsWith('_')) throw new UserError('Enter the site name, like nathan.woodburn.');
  if (checkRunning) throw new UserError('A check is already running. Try again in a moment.');
  checkRunning = true;
  try {
    hnsd.treeRoots.flush();
    const report = await runChecker(name);
    let live = null;
    try {
      const result = await hnsd.lookup(`_443._tcp.${name}`, 'TLSA');
      live = (result.answers || []).filter(a => a.type === 'TLSA').map(a => a.data);
    } catch (e) {
      live = null;
    }
    const proven = (report.tlsa || []).map(tlsaKey).sort();
    const current = (live || []).map(tlsaKey).sort();
    if (report.ok) {
      const same = live !== null && proven.length === current.length && proven.every((t, i) => t === current[i]);
      report.steps.push({
        id: 'live',
        ok: same,
        detail: same
          ? 'Matches the TLSA record Dit resolves right now through hnsd.'
          : live === null
            ? 'Dit could not look up the TLSA record right now to compare.'
            : `Differs from what Dit resolves right now (${current.join('; ') || 'nothing'}). The site may have changed its key since the proof was made.`,
      });
      report.ok = same;
    }
    return report;
  } finally {
    checkRunning = false;
  }
}

async function lookup(body) {
  const name = normalizeName(body.name);
  const type = LOOKUP_TYPES.includes(body.type) ? body.type : 'A';
  // TLSA records live at _443._tcp.<name>
  const qname = type === 'TLSA' && !name.startsWith('_') ? `_443._tcp.${name}` : name;
  const started = Date.now();
  try {
    const result = await hnsd.lookup(qname, type);
    return {name: qname, type, ms: Date.now() - started, ...result};
  } catch (e) {
    throw new UserError(`${e.message} hnsd may still be syncing: check the status above.`);
  }
}

function saveSettings(body) {
  if (!state.MODES.includes(body.mode)) throw new UserError('Unknown mode.');
  const settings = {...state.loadSettings(), mode: body.mode, savedAt: new Date().toISOString()};
  state.saveSettings(settings);
  return settings;
}

// ---------- HTTP ----------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, {...SECURITY_HEADERS, 'Cache-Control': 'no-store', ...headers});
  res.end(body);
}

const sendJson = (res, status, value) => send(res, status, JSON.stringify(value), {'Content-Type': 'application/json; charset=utf-8'});

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_JSON) {
        reject(new UserError('Request too large.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        resolve(value && typeof value === 'object' ? value : {});
      } catch (e) {
        reject(new UserError('Invalid JSON.'));
      }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const file = path.normalize(path.join(PUBLIC_DIR, relative));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 404, 'Not found');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    const type = MIME[path.extname(file)] || 'application/octet-stream';
    const cache = file.includes(`${path.sep}fonts${path.sep}`) ? 'public, max-age=604800' : 'no-cache';
    send(res, 200, req.method === 'HEAD' ? '' : data, {'Content-Type': type, 'Cache-Control': cache});
  });
}

async function handle(req, res) {
  if (!(await source.isTrustedSource(req.socket.remoteAddress))) {
    return send(res, 403, 'Open Dit from your Umbrel dashboard.');
  }
  const {pathname} = new URL(req.url, 'http://dit');

  if (pathname.startsWith('/api/')) {
    if (req.method === 'GET' && pathname === '/api/status') return sendJson(res, 200, await getStatus());
    if (req.method === 'GET' && pathname === '/api/log') return sendJson(res, 200, {lines: hnsd.log()});

    if (req.method === 'POST') {
      // A header other websites cannot add to a cross-site request: with the
      // JSON-only body, it stops them from changing settings through your browser.
      if (req.headers['x-dit'] !== '1') return sendJson(res, 403, {error: 'Missing X-Dit header.'});
      const body = await readJson(req);
      if (pathname === '/api/lookup') return sendJson(res, 200, await lookup(body));
      if (pathname === '/api/sane-check') return sendJson(res, 200, await saneCheck(body));
      if (pathname === '/api/settings') return sendJson(res, 200, saveSettings(body));
    }
    return sendJson(res, 404, {error: 'Not found.'});
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  return serveStatic(req, res, pathname);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(err => {
    if (err instanceof UserError) return sendJson(res, 400, {error: err.message});
    console.error('[Dit]', err);
    return sendJson(res, 500, {error: 'Something went wrong in Dit. Check the app logs.'});
  });
});

async function shutdown() {
  server.close();
  await hnsd.stop();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

hnsd.start();
server.listen(PORT, () => {
  console.log(`[Dit] Web UI on port ${PORT}. ${source.describe()}`);
});
