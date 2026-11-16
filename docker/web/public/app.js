'use strict';

// Dit's page: polls /api/status, runs test lookups and saves the listening mode.
// No framework; text is always set with textContent, never as HTML.

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

function renderSync(hnsd) {
  const percent = hnsd.progress === null ? 0 : Math.min(100, Math.round(hnsd.progress * 1000) / 10);
  $('sync-fill').style.width = `${hnsd.synced ? 100 : percent}%`;
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
}

function renderDns(dns, settings) {
  const error = $('dns-error');
  error.hidden = true;
  $('dns-mode').textContent = MODE_NAMES[settings.mode] || settings.mode;

  if (!dns) {
    $('dns-headline').textContent = 'Waiting for the DNS service…';
    $('dns-ports').textContent = '–';
    $('dns-addresses').textContent = '–';
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
  } else if (dns.effective === 'standalone') {
    $('dns-headline').textContent = lan.length ? `Ready at ${lan[0]}` : 'Ready on port 53';
  } else {
    $('dns-headline').textContent = `Ready as upstream on port ${dns.altPort}`;
  }

  let message = dns.error || '';
  if (!message && settings.mode === 'auto' && dns.effective === 'upstream') {
    message = `Another app on this Umbrel uses port 53, so Dit listens on port ${dns.altPort} only. `
      + 'Set it as the upstream of that app (see "Set up your devices").';
  }
  if (message) {
    error.textContent = message;
    error.hidden = false;
  }
}

function renderOverall(status) {
  const pill = $('overall');
  const listening = status.dns && status.dns.running && status.dns.ports.length > 0;
  if (status.hnsd.synced && listening) {
    pill.dataset.state = 'ok';
    pill.textContent = 'Resolving';
  } else if (!status.hnsd.running && !status.hnsd.reachable) {
    pill.dataset.state = 'fail';
    pill.textContent = 'Stopped';
  } else {
    pill.dataset.state = 'wait';
    pill.textContent = status.hnsd.reachable && !status.hnsd.synced ? 'Syncing' : 'Starting…';
  }
}

async function refresh() {
  try {
    const status = await api('status');
    renderSync(status.hnsd);
    renderDns(status.dns, status.settings);
    renderOverall(status);
    $('version').textContent = `Dit ${status.version}`;
    if (!modeTouched) {
      const radio = document.querySelector(`input[name="mode"][value="${status.settings.mode}"]`);
      if (radio) radio.checked = true;
    }
  } catch (e) {
    $('overall').dataset.state = 'fail';
    $('overall').textContent = 'Not reachable';
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
    box.append(el('p', reason, 'note'));
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
    $('lookup-result').replaceChildren(el('p', e.message, 'note fail'));
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
    saved.className = 'note';
    saved.textContent = 'Saved. The DNS service switches within a few seconds.';
    setTimeout(refresh, 4000);
  } catch (e) {
    saved.className = 'note fail';
    saved.textContent = e.message;
  } finally {
    $('mode-button').disabled = false;
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

$('log-details').addEventListener('toggle', event => {
  if (event.target.open) loadLog();
});

refresh();
setInterval(refresh, 5000);
setInterval(() => { if ($('log-details').open) loadLog(); }, 5000);
