'use strict';

// Dit's page: polls /api/status, runs test lookups and saves the listening mode.
// Pages are sections of index.html shown by the URL hash (#/, #/setup, #/mode, #/log).
// No framework; dynamic text is always set with textContent, never as HTML.

const $ = id => document.getElementById(id);
const MODE_NAMES = {
  auto: 'Automatic',
  standalone: 'DNS server for my network',
  upstream: 'Upstream for Pi-hole or AdGuard Home',
};

async function api(path, body) {
  const options = body === undefined
    ? {}
    : {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Dit': '1'}, body: JSON.stringify(body)};
  // Relative URL: works under whatever address Umbrel serves the app on
  const res = await fetch(`api/${path}`, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status}).`);
  return data;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function setAll(selector, text) {
  for (const node of document.querySelectorAll(selector)) node.textContent = text;
}

function ago(unixSeconds) {
  const minutes = Math.round((Date.now() / 1000 - unixSeconds) / 60);
  if (minutes < 1) return 'just now';
  if (minutes < 90) return `${minutes} min ago`;
  if (minutes < 60 * 36) return `${Math.round(minutes / 60)} hours ago`;
  return `${Math.round(minutes / 1440)} days ago`;
}

// ---------- status ----------

let modeTouched = false;

function setPill(id, state, text) {
  const pill = $(id);
  pill.className = `pill ${state}`;
  pill.textContent = text;
}

function renderSync(hnsd) {
  const percent = hnsd.progress === null ? 0 : Math.min(100, Math.round(hnsd.progress * 1000) / 10);
  $('sync-fill').style.width = `${hnsd.synced ? 100 : percent}%`;
  $('sync-bar').classList.toggle('done', !!hnsd.synced);
  $('sync-bar').setAttribute('aria-valuenow', String(hnsd.synced ? 100 : percent));
  $('sync-height').textContent = hnsd.height === null ? '–' : hnsd.height.toLocaleString('en');
  $('sync-peers').textContent = hnsd.peers === null ? '–' : String(hnsd.peers);
  $('sync-tip').textContent = hnsd.tipTime ? ago(hnsd.tipTime) : '–';

  let headline;
  let note = '';
  if (!hnsd.reachable) {
    headline = hnsd.running ? 'Starting hnsd…' : 'hnsd is not running';
    note = hnsd.lastExit ? `Last stop: ${hnsd.lastExit}. Dit restarts it automatically.` : '';
  } else if (hnsd.synced) {
    headline = 'Synced';
    note = 'Handshake names resolve and are verified against the blockchain.';
  } else if (hnsd.peers === 0) {
    headline = 'Looking for peers…';
    note = 'hnsd needs outgoing connections to the Handshake network. This can take a minute after a start.';
  } else {
    headline = `Syncing headers, ${percent}%`;
    note = 'The first sync takes a couple of minutes. Handshake lookups fail until it finishes; regular names already work.';
  }
  $('sync-headline').textContent = headline;
  $('sync-note').textContent = note;
  if (!hnsd.reachable) setPill('sync-pill', hnsd.running ? 'warn' : 'fail', hnsd.running ? 'Starting' : 'Stopped');
  else if (hnsd.synced) setPill('sync-pill', 'ok', 'Synced');
  else setPill('sync-pill', 'warn', 'Syncing');
}

function renderDns(dns, settings) {
  const error = $('dns-error');
  error.hidden = true;
  $('dns-mode').textContent = MODE_NAMES[settings.mode] || settings.mode;

  if (!dns) {
    $('dns-headline').textContent = 'Waiting for the DNS service…';
    $('dns-ports').textContent = '–';
    $('dns-addresses').textContent = '–';
    setPill('dns-pill', 'warn', 'Starting');
    return;
  }

  setAll('.alt-port', String(dns.altPort));
  const lan = dns.addresses.filter(a => !a.tailscale).map(a => a.address);
  const tailscale = dns.addresses.filter(a => a.tailscale).map(a => a.address);
  if (lan.length) setAll('.lan-ip', lan[0]);
  if (tailscale.length) setAll('.ts-ip', tailscale[0]);
  $('dns-addresses').textContent = [...lan, ...tailscale.map(ip => `${ip} (Tailscale)`)].join(', ') || '–';
  $('dns-ports').textContent = dns.ports.length ? dns.ports.map(port => `port ${port}`).join(' and ') : 'nothing';

  if (!dns.running || !dns.ports.length) {
    $('dns-headline').textContent = 'Not listening';
    setPill('dns-pill', 'fail', 'Not listening');
  } else if (dns.effective === 'standalone') {
    $('dns-headline').textContent = lan.length ? `Ready at ${lan[0]}` : 'Ready on port 53';
    setPill('dns-pill', 'ok', 'Port 53');
  } else {
    $('dns-headline').textContent = `Ready as upstream on port ${dns.altPort}`;
    setPill('dns-pill', 'ok', 'Upstream');
  }

  const portFree = settings.mode === 'auto' && dns.effective === 'upstream' && !!dns.mainPortFree;
  $('port-free').hidden = !portFree;

  let message = dns.error || '';
  if (!message && !portFree && settings.mode === 'auto' && dns.effective === 'upstream') {
    message = `Another app on this Umbrel uses port 53, so Dit listens on port ${dns.altPort} only. `
      + 'Set Dit as the upstream of that app (see "Set up devices"), or remove that app and choose "DNS server for my network".';
  }
  if (message) {
    $('dns-error-text').textContent = message;
    error.hidden = false;
  }
}

// The DANE proxy, on the Secure sites page. Its address is the Umbrel's LAN address.
function renderDane(dane, dns) {
  const lan = dns ? dns.addresses.filter(a => !a.tailscale).map(a => a.address) : [];
  const host = lan[0] || location.hostname;
  if (!dane) {
    setPill('dane-pill', 'fail', 'Not running');
    $('dane-headline').textContent = 'The DANE proxy is not running';
    $('dane-port').textContent = '–';
    $('dane-until').textContent = '–';
    $('dane-fingerprint').textContent = '–';
    return;
  }
  const base = `http://${host}:${dane.port}`;
  setAll('.dane-pac', `${base}/proxy.pac`);
  setAll('.dane-ca-text', `${base}/dit-dane.crt`);
  for (const link of document.querySelectorAll('.dane-ca')) link.href = `${base}/dit-dane.crt`;
  setPill('dane-pill', 'ok', 'Running');
  $('dane-headline').textContent = `Ready at ${host}:${dane.port}`;
  $('dane-port').textContent = String(dane.port);
  $('dane-until').textContent = new Date(dane.caNotAfter).toLocaleDateString('en', {year: 'numeric', month: 'short', day: 'numeric'});
  $('dane-fingerprint').textContent = dane.caFingerprint;
}

// ---------- Stateless DANE checker (beta) ----------

const SANE_STEPS = {
  proofs: 'Proofs',
  'urkel-decode': 'Urkel data',
  urkel: 'Blockchain proof',
  root: 'Tree root',
  ds: 'On-chain DNSSEC anchor',
  dnssec: 'DNSSEC chain',
  tlsa: 'TLSA record',
  live: 'Compared with Dit',
};

function renderTreeRoots(summary) {
  const line = $('sane-roots');
  if (!summary || !summary.count) {
    line.textContent = 'Dit has not collected tree roots from hnsd yet. They come in with new blocks and every time hnsd starts.';
    return;
  }
  const newest = summary.newestTime ? ago(summary.newestTime) : 'unknown';
  line.textContent = `Dit knows ${summary.count} tree roots from its own hnsd (newest from block ${summary.newestHeight.toLocaleString('en')}, ${newest}).`;
}

function renderSane(report) {
  const box = $('sane-result');
  const list = el('ul', undefined, 'check-list');
  for (const step of report.steps) {
    const li = el('li');
    li.append(el('span', step.ok ? '✓' : '✕', `check-icon ${step.ok ? 'ok' : 'fail'}`));
    const text = el('span');
    text.append(el('strong', SANE_STEPS[step.id] || step.id), el('span', step.detail, 'detail'));
    li.append(text);
    list.append(li);
  }
  box.replaceChildren(list);
  setPill('sane-pill', report.ok ? 'ok' : 'fail', report.ok ? 'Verified' : 'Not verified');
}

$('sane-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('sane-button');
  button.disabled = true;
  button.textContent = 'Checking…';
  setPill('sane-pill', 'idle', 'Checking…');
  try {
    renderSane(await api('sane-check', {name: $('sane-name').value}));
  } catch (e) {
    $('sane-result').replaceChildren(el('p', e.message, 'note inline fail'));
    setPill('sane-pill', 'fail', 'Error');
  } finally {
    button.disabled = false;
    button.textContent = 'Check';
  }
});

// The status panel at the bottom of the sidebar, and its short form in the phone header
function renderChrome(state, title, detail) {
  const dot = el('span', undefined, `dot ${state}`);
  const text = el('span');
  text.append(el('strong', title), el('span', detail, 'detail'));
  $('server-status').replaceChildren(dot, text);
  $('mobile-status').replaceChildren(el('span', undefined, `dot ${state}`), document.createTextNode(title));
}

function renderOverall(status) {
  const dns = status.dns;
  const listening = dns && dns.running && dns.ports.length > 0;
  const where = listening ? `port${dns.ports.length > 1 ? 's' : ''} ${dns.ports.join(' and ')}` : '';
  if (status.hnsd.synced && listening) {
    renderChrome('ok', 'Resolving', `hnsd synced · ${where}`);
  } else if (!status.hnsd.running && !status.hnsd.reachable) {
    renderChrome('fail', 'Stopped', 'hnsd is not running');
  } else if (status.hnsd.synced && !listening) {
    renderChrome('fail', 'Not listening', 'The DNS service has no port');
  } else {
    renderChrome('warn', status.hnsd.reachable ? 'Syncing' : 'Starting…', 'Handshake names resolve once synced');
  }
}

async function refresh() {
  try {
    const status = await api('status');
    renderSync(status.hnsd);
    renderDns(status.dns, status.settings);
    renderDane(status.dane, status.dns);
    renderTreeRoots(status.treeRoots);
    renderOverall(status);
    $('version').textContent = `Dit ${status.version}`;
    if (!modeTouched) {
      const radio = document.querySelector(`input[name="mode"][value="${status.settings.mode}"]`);
      if (radio) radio.checked = true;
    }
  } catch (e) {
    renderChrome('fail', 'Not reachable', 'Dit did not answer');
  }
}

// ---------- test a name ----------

function renderLookup(result) {
  const box = $('lookup-result');
  box.replaceChildren();

  const badges = el('div', undefined, 'badges');
  badges.append(el('span', result.rcode, `badge ${result.rcode === 'NOERROR' ? 'ok' : 'fail'}`));
  badges.append(el('span', result.authenticated ? 'DNSSEC validated' : 'Not DNSSEC validated', `badge ${result.authenticated ? 'ok' : ''}`));
  badges.append(el('span', `${result.ms} ms`, 'badge'));
  box.append(badges);

  if (!result.answers.length) {
    const reason = result.rcode === 'NXDOMAIN' ? 'This name does not exist.'
      : result.rcode === 'SERVFAIL' ? 'The resolver could not get a valid answer. If hnsd is still syncing, try again when it is done.'
      : `No ${result.type} records for ${result.name}.`;
    box.append(el('p', reason, 'note inline'));
    return;
  }

  const table = el('table');
  const head = el('tr');
  for (const title of ['Name', 'Type', 'TTL', 'Value']) head.append(el('th', title));
  table.append(head);
  for (const answer of result.answers) {
    const row = el('tr');
    for (const value of [answer.name, answer.type, String(answer.ttl), answer.data]) row.append(el('td', value));
    table.append(row);
  }
  const wrap = el('div', undefined, 'table-wrap');
  wrap.append(table);
  box.append(wrap);
}

$('lookup-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('lookup-button');
  button.disabled = true;
  button.textContent = 'Looking up…';
  try {
    renderLookup(await api('lookup', {name: $('lookup-name').value, type: $('lookup-type').value}));
  } catch (e) {
    $('lookup-result').replaceChildren(el('p', e.message, 'note inline fail'));
  } finally {
    button.disabled = false;
    button.textContent = 'Look up';
  }
});

// ---------- mode ----------

$('mode-form').addEventListener('change', () => { modeTouched = true; });

$('mode-form').addEventListener('submit', async event => {
  event.preventDefault();
  const chosen = document.querySelector('input[name="mode"]:checked');
  if (!chosen) return;
  const saved = $('mode-saved');
  $('mode-button').disabled = true;
  try {
    await api('settings', {mode: chosen.value});
    modeTouched = false;
    saved.className = 'note inline';
    saved.textContent = 'Saved. The DNS service switches within a few seconds.';
    setTimeout(refresh, 4000);
  } catch (e) {
    saved.className = 'note inline fail';
    saved.textContent = e.message;
  } finally {
    $('mode-button').disabled = false;
  }
});

// Saving "Automatic" again makes the DNS service decide again, starting with port 53
$('port-free-button').addEventListener('click', async () => {
  const button = $('port-free-button');
  button.disabled = true;
  button.textContent = 'Switching…';
  try {
    await api('settings', {mode: 'auto'});
    setTimeout(refresh, 4000);
  } catch (e) {
    $('dns-error-text').textContent = e.message;
    $('dns-error').hidden = false;
  } finally {
    setTimeout(() => {
      button.disabled = false;
      button.textContent = 'Use port 53';
    }, 4000);
  }
});

// ---------- log ----------

async function loadLog() {
  try {
    const {lines} = await api('log');
    $('log').textContent = lines.length ? lines.join('\n') : 'No log lines yet.';
  } catch (e) {
    $('log').textContent = e.message;
  }
}

// ---------- pages ----------

const PAGES = ['overview', 'setup', 'dane', 'mode', 'log'];
let currentPage = null;

function route() {
  const name = (location.hash || '#/').replace(/^#\/?/, '') || 'overview';
  const page = PAGES.includes(name) ? name : 'overview';
  for (const section of document.querySelectorAll('[data-page]')) section.hidden = section.dataset.page !== page;
  for (const link of document.querySelectorAll('[data-nav]')) {
    if (link.dataset.nav === page) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  closeMenu();
  if (page !== currentPage) {
    currentPage = page;
    window.scrollTo(0, 0);
    $('app').focus({preventScroll: true});
    if (page === 'log') loadLog();
  }
}

// ---------- menu (phones) ----------

const menuButton = $('menu-button');
const side = $('side');

function closeMenu() {
  side.classList.remove('open');
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-label', 'Open menu');
}

menuButton.addEventListener('click', () => {
  const open = !side.classList.contains('open');
  side.classList.toggle('open', open);
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
});

// ---------- light and dark theme ----------
// theme.js applies the theme before the page draws; this button switches it
// and remembers the choice in this browser.

const THEME_ICONS = {
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
};
const themeToggle = $('theme-toggle');

function showTheme() {
  const dark = document.documentElement.dataset.theme === 'dark';
  // Fixed markup only: the icons are constants above
  themeToggle.innerHTML = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${THEME_ICONS[dark ? 'sun' : 'moon']}</svg>`;
  themeToggle.append(dark ? 'Light mode' : 'Dark mode');
}

themeToggle.addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem('dit-theme', theme);
  } catch (e) {
    // private window or blocked storage: the choice lasts until the page closes
  }
  showTheme();
});

// No saved choice: follow the system when it switches (for example at sunset)
if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
    let saved = null;
    try { saved = localStorage.getItem('dit-theme'); } catch (e) {}
    if (saved) return;
    document.documentElement.dataset.theme = event.matches ? 'dark' : 'light';
    showTheme();
  });
}

// ---------- start ----------

showTheme();
window.addEventListener('hashchange', route);
route();
refresh();
setInterval(refresh, 5000);
setInterval(() => { if (currentPage === 'log') loadLog(); }, 5000);
