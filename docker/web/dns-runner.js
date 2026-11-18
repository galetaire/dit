'use strict';

// Dit's "dns" service: runs dnsproxy on the Umbrel's own network interfaces
// (host networking) and forwards everything to hnsd.
//
// Ports depend on the mode in settings.json (set from the web UI):
// - standalone: port 53 and the alternate port. Dit is the DNS server of the network.
// - upstream:   only the alternate port. Pi-hole or AdGuard Home keep port 53
//               and use Dit as their upstream resolver.
// - auto:       standalone if port 53 is free the first time, else upstream.
//               The decision is remembered, so it does not depend on which app
//               starts first after a reboot. Saving "auto" again from the web UI
//               forgets it and tries port 53 first.
//
// While only the alternate port is in use, port 53 is checked every 30s:
// standalone mode takes it as soon as it is free (that is what was asked for);
// auto mode only reports it (mainPortFree), so the web UI can offer it. Auto
// never takes it by itself: the other DNS app may just be restarting.
//
// It writes dns-state.json for the web UI: ports, errors and the Umbrel's addresses.
const {spawn} = require('child_process');
const dgram = require('dgram');
const net = require('net');
const os = require('os');
const state = require('./lib/state');

const DNSPROXY_BIN = process.env.DIT_DNSPROXY_BIN || 'dnsproxy';
const UPSTREAM = process.env.DIT_UPSTREAM || '127.0.0.1:15350';
const MAIN_PORT = Number(process.env.DIT_MAIN_PORT || 53);
const ALT_PORT = Number(process.env.DIT_ALT_PORT || 5300);
const CACHE_BYTES = Number(process.env.DIT_CACHE_BYTES || 8 * 1024 * 1024);
const POLL_MS = 2000;
const PROBE_MS = Number(process.env.DIT_PROBE_MS || 30000);
// dnsproxy binds its ports right away: alive after this long means they are ours
const SETTLE_MS = 2500;

let child = null;
let stopping = false;
let ipv6 = true;
let wantedMode = null;
let current = {
  mode: 'auto',
  // What "auto" decided, kept across restarts
  autoDecision: (state.loadDnsState() || {}).autoDecision || null,
  effective: null,
  ports: [],
  mainPortBusy: false,
  // Auto mode on the alternate port only, and port 53 has become free
  mainPortFree: false,
  error: null,
};

const log = message => console.log(`[dit-dns] ${message}`);

// The Umbrel's own addresses, for the setup instructions in the UI
function addresses() {
  const list = [];
  for (const [iface, entries] of Object.entries(os.networkInterfaces())) {
    // Skip Docker's bridges and container links
    if (/^(lo|docker|br-|veth|cni|flannel)/.test(iface)) continue;
    for (const entry of entries) {
      if (entry.internal || entry.family !== 'IPv4') continue;
      list.push({iface, address: entry.address, tailscale: /^tailscale/.test(iface)});
    }
  }
  return list;
}

function writeState() {
  try {
    state.saveDnsState({
      ...current,
      mainPort: MAIN_PORT,
      altPort: ALT_PORT,
      upstream: UPSTREAM,
      running: !!child,
      addresses: addresses(),
      updatedAt: new Date().toISOString(),
    });
  } catch (e) {
    log(`could not write the state file: ${e.message}`);
  }
}

function runProxy(ports) {
  return new Promise(resolve => {
    const args = ['-l', '0.0.0.0'];
    if (ipv6) args.push('-l', '::');
    for (const port of ports) args.push('-p', String(port));
    // --refuse-any: no ANY answers, the classic amplification query
    args.push('-u', UPSTREAM, '--cache', '--cache-size', String(CACHE_BYTES), '--refuse-any');
    log(`starting: ${DNSPROXY_BIN} ${args.join(' ')}`);

    let output = '';
    let settled = false;
    const proc = spawn(DNSPROXY_BIN, args, {stdio: ['ignore', 'pipe', 'pipe']});
    const onData = data => {
      const text = String(data);
      if (output.length < 16384) output += text;
      // Pass warnings and errors to the container log, not every query
      for (const line of text.split('\n')) {
        if (/ (WARN|ERROR) /.test(line)) console.log(line);
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);

    const timer = setTimeout(() => {
      settled = true;
      child = proc;
      resolve({ok: true});
    }, SETTLE_MS);

    proc.on('error', err => {
      clearTimeout(timer);
      if (!settled) resolve({ok: false, output: err.message});
    });
    proc.on('close', code => {
      clearTimeout(timer);
      if (!settled) {
        resolve({ok: false, output});
        return;
      }
      if (child === proc) child = null;
      if (stopping || proc.replaced) return;
      log(`dnsproxy stopped (exit code ${code}), restarting in 3s`);
      writeState();
      setTimeout(() => { if (!stopping) apply(true); }, 3000);
    });
  });
}

function stopProxy() {
  if (!child) return Promise.resolve();
  const proc = child;
  proc.replaced = true;
  child = null;
  return new Promise(resolve => {
    const timer = setTimeout(() => proc.kill('SIGKILL'), 5000);
    proc.once('close', () => { clearTimeout(timer); resolve(); });
    proc.kill('SIGTERM');
  });
}

// Which address:port could not be bound, from dnsproxy's error text
function bindFailure(output) {
  const match = /listen (?:udp|tcp) (\S+):(\d+): bind: (.+?)"?$/m.exec(output || '');
  return match ? {address: match[1], port: Number(match[2]), reason: match[3]} : null;
}

let applying = false;
let applyAgain = false;

// Start dnsproxy for the mode in settings.json. force: restart even if the mode is unchanged.
async function apply(force = false) {
  if (applying) {
    applyAgain = true;
    return;
  }
  applying = true;
  try {
    const settings = state.loadSettings();
    const mode = settings.mode;
    // savedAt changes on every save, so saving the same mode again retries port 53
    const wanted = `${mode}|${settings.savedAt || ''}`;
    // Unchanged settings: nothing to do. Crashes and failed starts are retried
    // by their own timers (force), not by this poll.
    if (!force && wanted === wantedMode) return;
    // Settings saved from the web UI since this runner started (not a restart):
    // saving "auto" again means "decide again", so try port 53 first
    if (wantedMode !== null && wanted !== wantedMode && mode === 'auto') current.autoDecision = null;
    wantedMode = wanted;
    await stopProxy();

    let effective = mode === 'auto' ? (current.autoDecision || 'standalone') : mode;
    current = {...current, mode, error: null, mainPortBusy: false, mainPortFree: false};

    for (let attempt = 0; attempt < 4; attempt++) {
      const ports = effective === 'standalone' ? [MAIN_PORT, ALT_PORT] : [ALT_PORT];
      const result = await runProxy(ports);
      if (result.ok) {
        if (mode === 'auto' && !current.autoDecision) current.autoDecision = effective;
        current.effective = effective;
        current.ports = ports;
        log(`listening on port${ports.length > 1 ? 's' : ''} ${ports.join(' and ')} (${effective} mode)`);
        return;
      }

      const failure = bindFailure(result.output);
      if (failure && failure.address === '[::]' && ipv6) {
        // No IPv6 on this host: listen on IPv4 only
        log('could not listen on IPv6, continuing with IPv4 only');
        ipv6 = false;
        continue;
      }
      if (failure && failure.port === MAIN_PORT && effective === 'standalone') {
        // Another app has port 53 (Pi-hole and AdGuard Home use it on Umbrel)
        log(`port ${MAIN_PORT} is in use by another app`);
        current.mainPortBusy = true;
        // Another DNS app lives here: stay out of its way after reboots too
        if (mode === 'auto') current.autoDecision = 'upstream';
        if (mode === 'standalone') {
          current.error = `Port ${MAIN_PORT} is used by another app on this Umbrel, so Dit is only listening on port ${ALT_PORT}.`;
        }
        effective = 'upstream';
        continue;
      }
      current.error = failure
        ? `Could not listen on ${failure.address}:${failure.port} (${failure.reason}).`
        : `dnsproxy did not start: ${(result.output || 'no output').trim().split('\n').pop()}`;
      break;
    }

    if (!child) {
      current.effective = null;
      current.ports = [];
      log(`${current.error || 'dnsproxy did not start'}; trying again in 15s`);
      setTimeout(() => { if (!stopping) apply(true); }, 15000);
    }
  } finally {
    applying = false;
    writeState();
    if (applyAgain) {
      applyAgain = false;
      apply();
    }
  }
}

// Can port 53 be bound right now (UDP and TCP, all IPv4 interfaces)?
// Binds for an instant and releases it.
function portIsFree(port) {
  const udp = new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    socket.once('error', () => { socket.close(); resolve(false); });
    socket.bind(port, '0.0.0.0', () => socket.close(() => resolve(true)));
  });
  const tcp = new Promise(resolve => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.listen(port, '0.0.0.0', () => server.close(() => resolve(true)));
  });
  return Promise.all([udp, tcp]).then(([a, b]) => a && b);
}

let probing = false;

async function probeMainPort() {
  // Only when listening on the alternate port alone, in a mode that wants port 53
  const onAltOnly = child && current.ports.length === 1 && current.ports[0] === ALT_PORT;
  if (stopping || applying || probing || !onAltOnly || current.mode === 'upstream') {
    if (current.mainPortFree && !onAltOnly) current.mainPortFree = false;
    return;
  }
  probing = true;
  try {
    const free = await portIsFree(MAIN_PORT);
    if (current.mode === 'standalone') {
      if (free) {
        log(`port ${MAIN_PORT} is free again, taking it`);
        await apply(true);
      }
    } else if (free !== current.mainPortFree) {
      current.mainPortFree = free;
      log(free ? `port ${MAIN_PORT} is free; choose it from the web page to use it` : `port ${MAIN_PORT} is in use again`);
      writeState();
    }
  } catch (e) {
    log(`could not check port ${MAIN_PORT}: ${e.message}`);
  } finally {
    probing = false;
  }
}

async function shutdown() {
  if (stopping) return;
  stopping = true;
  await stopProxy();
  writeState();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

log(`forwarding to hnsd at ${UPSTREAM}`);
apply(true);
// Pick up mode changes made in the web UI, and keep the state file fresh
setInterval(() => { if (!stopping) apply(); }, POLL_MS);
setInterval(() => { if (!stopping && !applying) writeState(); }, 10000);
setInterval(probeMainPort, PROBE_MS);
